#include "duckdb/catalog/catalog_entry/table_catalog_entry.hpp"
#include "duckdb/execution/physical_plan_generator.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/planner/expression/bound_operator_expression.hpp"
#include "duckdb/planner/expression/bound_reference_expression.hpp"
#include "duckdb/planner/operator/logical_create_index.hpp"
#include "duckdb/planner/operator/logical_get.hpp"
#include "duckdb/execution/operator/scan/physical_dummy_scan.hpp"
#include "duckdb/execution/operator/filter/physical_filter.hpp"
#include "duckdb/execution/operator/order/physical_order.hpp"
#include "duckdb/execution/operator/projection/physical_projection.hpp"
#include "duckdb/execution/operator/schema/physical_create_index.hpp"
#include "duckdb/catalog/catalog_entry/duck_table_entry.hpp"
#include "duckdb/planner/operator/logical_projection.hpp"

#include <duckdb/parser/parser.hpp>

namespace duckdb {

static PhysicalOperator &AddCreateIndex(PhysicalPlanGenerator &plan, LogicalCreateIndex &op, PhysicalOperator &prev,
                                        const IndexType &index_type, unique_ptr<IndexBuildBindData> bind_data) {
	PhysicalOperator &cindex = [&]() -> PhysicalOperator & {
		return plan.Make<PhysicalCreateIndex>(op, op.table, op.info->column_ids, std::move(op.info),
		                                      std::move(op.unbound_expressions), op.estimated_cardinality, index_type,
		                                      std::move(bind_data), std::move(op.alter_table_info));
	}();

	cindex.children.push_back(prev);
	return cindex;
}

static PhysicalOperator &AddFilter(PhysicalPlanGenerator &plan, LogicalCreateIndex &op, PhysicalOperator &prev) {
	auto cardinality = op.estimated_cardinality;

	auto filter_types = vector<LogicalType>();
	auto filter_exprs = vector<unique_ptr<Expression>>();

	for (idx_t i = 0; i < prev.types.size() - 1; i++) {
		filter_types.push_back(prev.types[i]);
		auto is_not_null_expr =
		    make_uniq<BoundOperatorExpression>(ExpressionType::OPERATOR_IS_NOT_NULL, LogicalType::BOOLEAN);
		auto bound_ref = make_uniq<BoundReferenceExpression>(prev.types[i], i);
		is_not_null_expr->children.push_back(std::move(bound_ref));

		filter_exprs.push_back(std::move(is_not_null_expr));
	}
	filter_types.push_back(LogicalType::ROW_TYPE);

	// filter operator
	auto &filter = plan.Make<PhysicalFilter>(std::move(filter_types), std::move(filter_exprs), cardinality);

	filter.children.push_back(prev);

	return filter;
}

static PhysicalOperator &AddProjection(PhysicalPlanGenerator &plan, LogicalCreateIndex &op, PhysicalOperator &prev) {
	auto cardinality = op.estimated_cardinality;

	// Create a projection on the indexed columns + rowid
	auto select_types = vector<LogicalType>();
	auto select_exprs = vector<unique_ptr<Expression>>();

	for (auto &expression : op.expressions) {
		select_types.push_back(expression->return_type);
		select_exprs.push_back(std::move(expression));
	}

	auto rowid_column_index = op.info->scan_types.size() - 1;
	select_types.push_back(LogicalType::ROW_TYPE);
	select_exprs.push_back(make_uniq<BoundReferenceExpression>(LogicalType::ROW_TYPE, rowid_column_index));

	auto &select = plan.Make<PhysicalProjection>(std::move(select_types), std::move(select_exprs), cardinality);

	select.children.push_back(prev);

	return select;
}

static PhysicalOperator &AddSort(PhysicalPlanGenerator &plan, LogicalCreateIndex &op, PhysicalOperator &prev) {
	auto cardinality = op.estimated_cardinality;

	vector<BoundOrderByNode> orders;
	vector<idx_t> projections;
	for (idx_t i = 0; i < prev.types.size() - 1; i++) {
		auto col_expr = make_uniq_base<Expression, BoundReferenceExpression>(prev.types[i], i);
		orders.emplace_back(OrderType::ASCENDING, OrderByNullType::NULLS_FIRST, std::move(col_expr));
		projections.emplace_back(i);
	}
	// add row id column to projections
	projections.emplace_back(prev.types.size() - 1);

	auto &sortby = plan.Make<PhysicalOrder>(prev.types, std::move(orders), std::move(projections), cardinality, true);

	sortby.children.push_back(prev);

	return sortby;
}

static void ReplaceInExpression(Expression &expr, idx_t old_idx, idx_t new_idx) {
	// Handle the current expression node if it's a column reference
	if (expr.GetExpressionClass() == ExpressionClass::BOUND_COLUMN_REF) {
		auto &col_ref = expr.Cast<BoundColumnRefExpression>();
		if (col_ref.binding.table_index == old_idx) {
			col_ref.binding.table_index = new_idx;
		}
	}
	// Use ExpressionIterator::EnumerateChildren to recurse into sub-expressions
	// (e.g., arguments of a function call or operands of an operator)
	ExpressionIterator::EnumerateChildren(expr, [&](unique_ptr<Expression> &child) {
		ReplaceInExpression(*child, old_idx, new_idx);
	});
}

static void Replace(LogicalOperator &op, idx_t old_index, idx_t new_index) {
	// 1. Remap expressions held directly by this operator
	for (auto &expr : op.expressions) {
		ReplaceInExpression(*expr, old_index, new_index);
	}

	// 2. Recurse into children operators (the plan tree)
	for (auto &child : op.children) {
		Replace(*child, old_index, new_index);
	}
}


unique_ptr<LogicalProjection> CreatePlanFromSQLString(ClientContext &context, const string &sql_query) {
    Parser parser;
    parser.ParseQuery(sql_query);
    if (parser.statements.empty()) {
        throw InternalException("CreatePlanFromSQLString: No statements found.");
    }

    auto &statement = parser.statements[0];
    if (statement->type != StatementType::SELECT_STATEMENT) {
        throw InternalException("CreatePlanFromSQLString: Only SELECT statements supported.");
    }

    auto binder = Binder::CreateBinder(context);
    auto bound_statement = binder->Bind(*statement);
    auto plan = std::move(bound_statement.plan);

    // FIX: If the root is already a projection, we use unique_ptr_cast to convert
    // from unique_ptr<LogicalOperator> to unique_ptr<LogicalProjection>.
    if (plan->type == LogicalOperatorType::LOGICAL_PROJECTION) {
        return unique_ptr_cast<LogicalOperator, LogicalProjection>(std::move(plan));
    }

    // MANUAL WRAPPING: If it's a LogicalGet or LogicalFilter, we create the projection here.
    auto table_index = binder->GenerateTableIndex();
    vector<unique_ptr<Expression>> select_list;
    for (idx_t i = 0; i < bound_statement.types.size(); i++) {
        // We create a reference to the i-th column of the child (plan).
        // In an isolated binder, the child table index is usually 0.
        select_list.push_back(make_uniq<BoundColumnRefExpression>(
            bound_statement.types[i],
            ColumnBinding(table_index, i)
        ));
    }

    // This constructor returns a unique_ptr<LogicalProjection> directly.
    auto projection = make_uniq<LogicalProjection>(table_index, std::move(select_list));
    projection->children.push_back(std::move(plan));

    return projection;
}


void GraftTransformationPlan(ClientContext &context, LogicalOperator &index_op, const string &transform_sql) {
	if (index_op.type != LogicalOperatorType::LOGICAL_CREATE_INDEX){
		throw InternalException("GraftTransformationPlan: Operator is not an Index creation operator");
		}

	// 1. Get our transformation projection (it has its own unique table_index)
	auto sub_plan = CreatePlanFromSQLString(context, transform_sql);
	idx_t sub_plan_output_idx = sub_plan->table_index;

	// 2. Identify the original source of data (the table scan)
	auto &original_scan = index_op.children[0];
	auto scan_indices = original_scan->GetTableIndex();
	if (scan_indices.empty()) {
		throw InternalException("GraftTransformationPlan: Source scan has no table index.");
	}
	idx_t actual_source_idx = scan_indices[0];

	// 3. REMAP THE SUB-PLAN:
	// The sub-plan expressions currently point to '0'.
	// We update them to point to the actual table scan (actual_source_idx).
	Replace(*sub_plan, 0, actual_source_idx);

	// 4. REMAP THE INDEX OPERATOR (Crucial Fix for the "Unknown Type" Error):
	// The index_op's expressions (the keys) currently point to the 'actual_source_idx'.
	// Since we are putting 'sub_plan' in the middle, the index_op's expressions
	// MUST now point to the output of the 'sub_plan' (sub_plan_output_idx).
	for (auto &expr : index_op.expressions) {
		ReplaceInExpression(*expr, actual_source_idx, sub_plan_output_idx);
	}

	// 5. STITCH THE TREE:
	// Discard the dummy child scan from the sub-plan and plug in the real one.
	sub_plan->children.clear();
	sub_plan->children.push_back(std::move(original_scan));

	// Finally, set the transformation as the new child of the index operator.
	index_op.children[0] = std::move(sub_plan);
}

PhysicalOperator &PhysicalPlanGenerator::CreatePlan(LogicalCreateIndex &op) {
	// Early-out, if the index already exists.
	auto &schema = op.table.schema;
	auto entry = schema.GetEntry(schema.GetCatalogTransaction(context), CatalogType::INDEX_ENTRY, op.info->index_name);
	if (entry) {
		if (op.info->on_conflict != OnCreateConflict::IGNORE_ON_CONFLICT) {
			throw CatalogException("Index with name \"%s\" already exists!", op.info->index_name);
		}
		return Make<PhysicalDummyScan>(op.types, op.estimated_cardinality);
	}

	if (!op.table.IsDuckTable()) {
		throw BinderException("Indexes can only be created on DuckDB tables.");
	}

	// Ensure that all expressions contain valid scalar functions.
	// E.g., get_current_timestamp(), random(), and sequence values cannot be index keys.
	for (idx_t i = 0; i < op.unbound_expressions.size(); i++) {
		auto &expr = op.unbound_expressions[i];
		if (!expr->IsConsistent()) {
			throw BinderException("Index keys cannot contain expressions with side effects.");
		}
	}

	// If we get here and the index type is not valid index type, we throw an exception.
	const auto index_type = context.db->config.GetIndexTypes().FindByName(op.info->index_type);

	if (!index_type) {
		throw BinderException("Unknown index type: " + op.info->index_type);
	}

	// Add a dependency for the entire table on which we create the index.
	dependencies.AddDependency(op.table);
	D_ASSERT(op.info->scan_types.size() - 1 <= op.info->names.size());
	D_ASSERT(op.info->scan_types.size() - 1 <= op.info->column_ids.size());

	D_ASSERT(op.children.size() == 1);

	// Index has a plan replacement function
	if (index_type->create_plan) {
		auto &scan = CreatePlan(*op.children[0]);
		PlanIndexInput input(context, op, *this, scan, index_type->index_info);
		return index_type->create_plan(input);
	}

	// Fall back to generic index creation plan
	// SCAN -> PROJECTION -> [FILTER] -> [SORT] -> CREATE INDEX

	// "Bind" the index and determine if we need a sort.
	auto &duck_table = op.table.Cast<DuckTableEntry>();
	IndexBuildBindInput bind_input {context, duck_table, *op.info, op.unbound_expressions};
	auto bind_data = index_type->build_bind(bind_input);

	// If the index requests a custom query, we need to embed into our plan now
	if (bind_data && !bind_data->query.empty()) {
		// we get a logical projection
		auto child_plan = CreatePlanFromSQLString(context, bind_data->query);

		// we create a new subplan
		auto &inner = CreatePlan(*child_plan);

		return AddCreateIndex(*this, op, inner, *index_type, std::move(bind_data));
	}

	bool need_sort = false;

	// if build_sort contains a callback
	if (index_type->build_sort) {
		IndexBuildSortInput sort_input {bind_data.get()};
		need_sort = index_type->build_sort(sort_input);
	}

	// Determine if this is a fresh index creation or an ALTER TABLE ADD INDEX
	auto need_filter = op.alter_table_info == nullptr;

	auto &scan = CreatePlan(*op.children[0]);

	// Construct the plan
	auto plan = &scan;
	plan = &AddProjection(*this, op, *plan);

	if (need_filter) {
		plan = &AddFilter(*this, op, *plan);
	}

	if (need_sort) {
		plan = &AddSort(*this, op, *plan);
	}

	plan = &AddCreateIndex(*this, op, *plan, *index_type, std::move(bind_data));
	return *plan;
}

} // namespace duckdb

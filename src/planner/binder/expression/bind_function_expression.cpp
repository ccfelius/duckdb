#include "duckdb/catalog/catalog.hpp"
#include "duckdb/catalog/catalog_entry/scalar_function_catalog_entry.hpp"
#include "duckdb/execution/expression_executor.hpp"
#include "duckdb/parser/expression/function_expression.hpp"
#include "duckdb/planner/expression/bound_cast_expression.hpp"
#include "duckdb/planner/expression/bound_constant_expression.hpp"
#include "duckdb/planner/expression/bound_function_expression.hpp"
#include "duckdb/planner/expression_binder.hpp"
#include "duckdb/planner/binder.hpp"

namespace duckdb {

BindResult ExpressionBinder::BindExpression(FunctionExpression &function, idx_t depth,
                                            unique_ptr<ParsedExpression> *expr_ptr) {
	// lookup the function in the catalog
	QueryErrorContext error_context(binder.root_statement, function.query_location);

	if (function.function_name == "unnest" || function.function_name == "unlist") {
		// special case, not in catalog
		// TODO make sure someone does not create such a function OR
		// have unnest live in catalog, too
		return BindUnnest(function, depth);
	}
	auto &catalog = Catalog::GetCatalog(context);
	auto func = catalog.GetEntry(context, CatalogType::SCALAR_FUNCTION_ENTRY, function.schema, function.function_name,
	                             false, error_context);
	switch (func->type) {
	case CatalogType::SCALAR_FUNCTION_ENTRY:
		// scalar function
		if (function.function_name == "list_transform") {
			// distinguish between lambda functions and the JSON operator ->
			BindFunction(function, (ScalarFunctionCatalogEntry *)func, depth, true);
		}
		return BindFunction(function, (ScalarFunctionCatalogEntry *)func, depth, false);
	case CatalogType::MACRO_ENTRY:
		// macro function
		return BindMacro(function, (ScalarMacroCatalogEntry *)func, depth, expr_ptr);
	default:
		// aggregate function
		return BindAggregate(function, (AggregateFunctionCatalogEntry *)func, depth);
	}
}

BindResult ExpressionBinder::BindFunction(FunctionExpression &function, ScalarFunctionCatalogEntry *func, idx_t depth,
                                          bool is_lambda) {

	// bind the children of the function expression
	string error;

	if (is_lambda) { // bind the lambda child separately

		D_ASSERT(function.children.size() == 2);

		// bind the list parameter
		BindChild(function.children[0], depth, error);

		// get the logical type of the children of the list
		auto &list_child = (BoundExpression &)*function.children[0];
		D_ASSERT(list_child.expr->return_type.id() == LogicalTypeId::LIST);
		auto list_child_type = ListType::GetChildType(list_child.expr->return_type);

		// bind the lambda parameter
		auto &lambda_expr = (LambdaExpression &)*function.children[1];
		BindResult result = BindExpression(lambda_expr, depth, true, list_child_type);

		if (result.HasError()) {
			error = result.error;
		} else {
			// successfully bound: replace the node with a BoundExpression
			auto alias = function.children[1]->alias;
			function.children[1] = make_unique<BoundExpression>(move(result.expression));
			auto be = (BoundExpression *)function.children[1].get();
			D_ASSERT(be);
			be->alias = alias;
			if (!alias.empty()) {
				be->expr->alias = alias;
			}
		}

	} else { // normal bind of each child
		for (idx_t i = 0; i < function.children.size(); i++) {
			BindChild(function.children[i], depth, error);
		}
	}

	if (!error.empty()) {
		return BindResult(error);
	}
	if (binder.GetBindingMode() == BindingMode::EXTRACT_NAMES) {
		return BindResult(make_unique<BoundConstantExpression>(Value(LogicalType::SQLNULL)));
	}

	// all children bound successfully
	// extract the children and types
	vector<unique_ptr<Expression>> children;
	for (idx_t i = 0; i < function.children.size(); i++) {
		auto &child = (BoundExpression &)*function.children[i];
		D_ASSERT(child.expr);
		children.push_back(move(child.expr));
	}
	unique_ptr<Expression> result =
	    ScalarFunction::BindScalarFunction(context, *func, move(children), error, function.is_operator);
	if (!result) {
		throw BinderException(binder.FormatError(function, error));
	}
	return BindResult(move(result));
}

BindResult ExpressionBinder::BindAggregate(FunctionExpression &expr, AggregateFunctionCatalogEntry *function,
                                           idx_t depth) {
	return BindResult(binder.FormatError(expr, UnsupportedAggregateMessage()));
}

BindResult ExpressionBinder::BindUnnest(FunctionExpression &expr, idx_t depth) {
	return BindResult(binder.FormatError(expr, UnsupportedUnnestMessage()));
}

string ExpressionBinder::UnsupportedAggregateMessage() {
	return "Aggregate functions are not supported here";
}

string ExpressionBinder::UnsupportedUnnestMessage() {
	return "UNNEST not supported here";
}

} // namespace duckdb

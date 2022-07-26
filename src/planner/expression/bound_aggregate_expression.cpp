#include "duckdb/planner/expression/bound_aggregate_expression.hpp"
#include "duckdb/parser/expression/function_expression.hpp"

#include "duckdb/catalog/catalog_entry/aggregate_function_catalog_entry.hpp"
#include "duckdb/common/types/hash.hpp"
#include "duckdb/common/field_writer.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/planner/expression/bound_cast_expression.hpp"

namespace duckdb {

BoundAggregateExpression::BoundAggregateExpression(AggregateFunction function, vector<unique_ptr<Expression>> children,
                                                   unique_ptr<Expression> filter, unique_ptr<FunctionData> bind_info,
                                                   bool distinct)
    : Expression(ExpressionType::BOUND_AGGREGATE, ExpressionClass::BOUND_AGGREGATE, function.return_type),
      function(move(function)), children(move(children)), bind_info(move(bind_info)), distinct(distinct),
      filter(move(filter)) {
	D_ASSERT(!function.name.empty());
}

string BoundAggregateExpression::ToString() const {
	return FunctionExpression::ToString<BoundAggregateExpression, Expression>(*this, string(), function.name, false,
	                                                                          distinct, filter.get());
}

hash_t BoundAggregateExpression::Hash() const {
	hash_t result = Expression::Hash();
	result = CombineHash(result, function.Hash());
	result = CombineHash(result, duckdb::Hash(distinct));
	return result;
}

bool BoundAggregateExpression::Equals(const BaseExpression *other_p) const {
	if (!Expression::Equals(other_p)) {
		return false;
	}
	auto other = (BoundAggregateExpression *)other_p;
	if (other->distinct != distinct) {
		return false;
	}
	if (other->function != function) {
		return false;
	}
	if (children.size() != other->children.size()) {
		return false;
	}
	if (!Expression::Equals(other->filter.get(), filter.get())) {
		return false;
	}
	for (idx_t i = 0; i < children.size(); i++) {
		if (!Expression::Equals(children[i].get(), other->children[i].get())) {
			return false;
		}
	}
	if (!FunctionData::Equals(bind_info.get(), other->bind_info.get())) {
		return false;
	}
	return true;
}

bool BoundAggregateExpression::PropagatesNullValues() const {
	return function.null_handling == FunctionNullHandling::SPECIAL_HANDLING ? false
	                                                                        : Expression::PropagatesNullValues();
}

unique_ptr<Expression> BoundAggregateExpression::Copy() {
	vector<unique_ptr<Expression>> new_children;
	for (auto &child : children) {
		new_children.push_back(child->Copy());
	}
	auto new_bind_info = bind_info ? bind_info->Copy() : nullptr;
	auto new_filter = filter ? filter->Copy() : nullptr;
	auto copy = make_unique<BoundAggregateExpression>(function, move(new_children), move(new_filter),
	                                                  move(new_bind_info), distinct);
	copy->CopyProperties(*this);
	return move(copy);
}

////! The bound function expression
// AggregateFunction function;

void BoundAggregateExpression::Serialize(FieldWriter &writer) const {
	D_ASSERT(!function.name.empty());
	writer.WriteString(function.name);
	writer.WriteSerializableList(children);
	writer.WriteField(distinct);
	writer.WriteOptional(filter);
	;

	if (!function.serialize) {
		throw InvalidInputException("Can't serialize aggregate function %s", function.name);
	}
	function.serialize(writer, bind_info.get(), function);
}

unique_ptr<Expression> BoundAggregateExpression::Deserialize(ClientContext &context, ExpressionType type,
                                                             FieldReader &reader) {
	auto name = reader.ReadRequired<string>();
	auto children = reader.ReadRequiredSerializableList<Expression>(context);
	auto distinct = reader.ReadRequired<bool>();

	unique_ptr<Expression> filter;
	filter = reader.ReadOptional<Expression>(move(filter), context);

	// TODO this is duplicated in logical_get more or less, make it a template or so
	auto &catalog = Catalog::GetCatalog(context);
	auto func_catalog = catalog.GetEntry(context, CatalogType::AGGREGATE_FUNCTION_ENTRY, DEFAULT_SCHEMA, name);

	if (!func_catalog || func_catalog->type != CatalogType::AGGREGATE_FUNCTION_ENTRY) {
		throw InternalException("Cant find catalog entry for function %s", name);
	}

	auto functions = (AggregateFunctionCatalogEntry *)func_catalog;
	auto function = functions->functions[0];

	unique_ptr<FunctionData> bind_info;
	bind_info = functions->functions[0].deserialize(context, reader, function);

	return make_unique<BoundAggregateExpression>(function, move(children), move(filter), move(bind_info), distinct);
}

} // namespace duckdb

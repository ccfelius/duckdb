#include "duckdb/planner/expression/bound_function_expression.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/parser/expression/bound_expression.hpp"
#include "duckdb/function/scalar/nested_functions.hpp"
#include "duckdb/common/types/chunk_collection.hpp"
#include "duckdb/common/types/data_chunk.hpp"
#include "duckdb/common/pair.hpp"

namespace duckdb {

static void ListValueFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	//	auto &func_expr = (BoundFunctionExpression &)state.expr;
	//	auto &info = (VariableReturnBindData &)*func_expr.bind_info;

	D_ASSERT(result.GetType().id() == LogicalTypeId::LIST);
	D_ASSERT(result.GetType().child_types().size() == 1);

	auto list_child = make_unique<ChunkCollection>();
	ListVector::SetEntry(result, move(list_child));

	auto &cc = ListVector::GetEntry(result);
	DataChunk append_vals;
	vector<LogicalType> types;
	if (args.ColumnCount() > 0) {
		types.push_back(args.GetTypes()[0]);
		append_vals.Initialize(types);
		append_vals.SetCardinality(1);
	}
	result.SetVectorType(VectorType::CONSTANT_VECTOR);
	for (idx_t i = 0; i < args.ColumnCount(); i++) {
		if (args.data[i].GetVectorType() != VectorType::CONSTANT_VECTOR) {
			result.SetVectorType(VectorType::FLAT_VECTOR);
		}
	}

	auto result_data = FlatVector::GetData<list_entry_t>(result);
	for (idx_t i = 0; i < args.size(); i++) {
		result_data[i].offset = cc.Count();
		for (idx_t col_idx = 0; col_idx < args.ColumnCount(); col_idx++) {
			append_vals.SetValue(0, 0, args.GetValue(col_idx, i).CastAs(types[0])); // FIXME evil pattern
			cc.Append(append_vals);
		}
		result_data[i].length = args.ColumnCount();
	}
	result.Verify(args.size());
}

static unique_ptr<FunctionData> ListValueBind(ClientContext &context, ScalarFunction &bound_function,
                                              vector<unique_ptr<Expression>> &arguments) {
	// collect names and deconflict, construct return type
	child_list_t<LogicalType> child_types;
	if (!arguments.empty()) {
		child_types.push_back(make_pair("", arguments[0]->return_type));
	} else {
		child_types.push_back(make_pair("", LogicalType::SQLNULL));
	}

	// this is more for completeness reasons
	bound_function.return_type = LogicalType(LogicalTypeId::LIST, move(child_types));
	return make_unique<VariableReturnBindData>(bound_function.return_type);
}

void ListValueFun::RegisterFunction(BuiltinFunctions &set) {
	// the arguments and return types are actually set in the binder function
	ScalarFunction fun("list_value", {}, LogicalType::LIST, ListValueFunction, false, ListValueBind);
	fun.varargs = LogicalType::ANY;
	set.AddFunction(fun);
	fun.name = "list_pack";
	set.AddFunction(fun);
}

} // namespace duckdb

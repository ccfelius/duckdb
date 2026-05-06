#include "duckdb.hpp"
#include "duckdb/execution/expression_executor.hpp"
#include "duckdb/function/window/window_shared_expressions.hpp"
#include "duckdb/optimizer/optimizer_extension.hpp"
#include "duckdb/planner/expression/bound_window_expression.hpp"
#include "duckdb/planner/operator/logical_get.hpp"
#include "duckdb/planner/filter/expression_filter.hpp"
#include "duckdb/storage/statistics/numeric_stats.hpp"
#include "duckdb/catalog/catalog_entry/table_catalog_entry.hpp"
#include "duckdb/planner/expression/bound_function_expression.hpp"
#include "duckdb/execution/expression_executor_state.hpp"
#include "duckdb/planner/expression/bound_reference_expression.hpp"
#include "duckdb/parser/parser_extension.hpp"
#include "duckdb/parser/parsed_data/create_table_function_info.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/parser/parsed_data/create_scalar_function_info.hpp"
#include "duckdb/parser/parsed_data/create_table_info.hpp"
#include "duckdb/parser/parsed_data/create_type_info.hpp"
#include "duckdb/main/database_manager.hpp"
#include "duckdb/transaction/meta_transaction.hpp"
#include "duckdb/planner/extension_callback.hpp"
#include "duckdb/planner/planner_extension.hpp"
#include "duckdb/planner/binder.hpp"
#include "duckdb/planner/operator/logical_projection.hpp"
#include "duckdb/planner/expression/bound_columnref_expression.hpp"
#include "duckdb/function/cast/cast_function_set.hpp"
#include "duckdb/function/window/window_executor.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/common/exception/conversion_exception.hpp"
#include "duckdb/planner/expression/bound_constant_expression.hpp"
#include "duckdb/common/extension_type_info.hpp"
#include "duckdb/common/vector/struct_vector.hpp"
#include "duckdb/parser/sql_statement.hpp"
#include "duckdb/parser/query_node/select_node.hpp"
#include "duckdb/parser/expression/constant_expression.hpp"
#include "duckdb/parser/tableref/emptytableref.hpp"

using namespace duckdb;

static void LoadableExtensionExplicitSchema(DataChunk &args, ExpressionState &state, Vector &result) {
	result.Reference(Value("Hello from the explicit_extension_schema schema!"), count_t(args.size()));
}

static void LoadableExtensionExplicitSchemaFunInit(ExtensionLoader &loader) {
	loader.RegisterFunction(
	    ScalarFunction("dedicated_schema_function", {}, LogicalType::VARCHAR, LoadableExtensionExplicitSchema));
}

extern "C" {
DUCKDB_CPP_EXTENSION_ENTRY(explicit_extension_schema, loader) {

	// set the schema for the extension
	loader.SetExtensionSchema("explicit_schema");
	LoadableExtensionExplicitSchemaFunInit(loader);
}
}

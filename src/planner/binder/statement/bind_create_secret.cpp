#include "duckdb/planner/binder.hpp"
#include "duckdb/parser/statement/pragma_statement.hpp"
#include "duckdb/planner/operator/logical_create_secret.hpp"
#include "duckdb/catalog/catalog_entry/pragma_function_catalog_entry.hpp"
#include "duckdb/catalog/catalog.hpp"
#include "duckdb/function/function_binder.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/parser/statement/create_secret_statement.hpp"
#include "duckdb/catalog/catalog_entry/create_secret_function_catalog_entry.hpp"

namespace duckdb {

BoundStatement Binder::Bind(CreateSecretStatement &stmt) {
	auto type = stmt.info->type;
	auto provider = stmt.info->provider;

	if (stmt.info->provider.empty()) {
		auto secret_type = context.db->config.secret_manager->LookupType(type);
		stmt.info->provider = secret_type.default_provider;
	}

	auto &entry = Catalog::GetEntry<CreateSecretFunctionCatalogEntry>(context, INVALID_CATALOG, DEFAULT_SCHEMA, type);
	string error;
	FunctionBinder function_binder(context);
	idx_t bound_idx = function_binder.BindFunction(entry.name, entry.functions, *stmt.info, error);
	if (bound_idx == DConstants::INVALID_INDEX) {
		throw BinderException(FormatError(stmt.stmt_location, error));
	}
	auto bound_function = entry.functions.GetFunctionByOffset(bound_idx);
	if (!bound_function.function) {
		throw BinderException("CREATE SECRET function does not have a function specified");
	}

	// bind and check named params
	QueryErrorContext error_context(root_statement, stmt.stmt_location);
	BindNamedParameters(bound_function.named_parameters, stmt.info->named_parameters, error_context,
	                    bound_function.name);

	BoundStatement result;
	result.names = {"Success"};
	result.types = {LogicalType::BOOLEAN};
	result.plan = make_uniq<LogicalCreateSecret>(bound_function, *stmt.info);
	properties.return_type = StatementReturnType::QUERY_RESULT;
	return result;
}

} // namespace duckdb

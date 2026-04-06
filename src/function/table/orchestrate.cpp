#include "duckdb/function/table/orchestrate.hpp"

#include "duckdb/common/string_util.hpp"
#include "duckdb/function/built_in_functions.hpp"
#include "duckdb/function/function_set.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/parser/keyword_helper.hpp"
#include "duckdb/parser/parser.hpp"
#include "duckdb/parser/tableref/subqueryref.hpp"
#include "duckdb/parser/statement/select_statement.hpp"

#ifndef DISABLE_DUCKDB_REMOTE_INSTALL
#ifndef DUCKDB_DISABLE_EXTENSION_LOAD
#include "httplib.hpp"
#endif
#endif

namespace duckdb {

// this can be omitted, just the format of worker address needs to be changed
static string FetchWorkerAddress(const string &orchestrator_address, const string &client_id) {
	auto scheme_end = orchestrator_address.find("://");

	auto host_start = (scheme_end != string::npos) ? scheme_end + 3 : 0;
	auto slash_pos = orchestrator_address.find('/', host_start);

	string proto_host_port =
	    (slash_pos != string::npos) ? orchestrator_address.substr(0, slash_pos) : orchestrator_address;

	string endpoint_path = (slash_pos != string::npos && slash_pos + 1 < orchestrator_address.size())
	                           ? orchestrator_address.substr(slash_pos)
	                           : "/worker";

	duckdb_httplib::Client client(proto_host_port);
	client.set_connection_timeout(10);
	client.set_read_timeout(30);

	// POST client_id in the request body; Go handler reads it from the body.
	auto res = client.Post(endpoint_path, client_id, "text/plain");

	if (!res) {
		throw IOException("orchestrate(): request to orchestrator failed: %s", to_string(res.error()));
	}

	if (res->status != 200) {
		throw IOException("orchestrate(): orchestrator returned msg %d: %s", res->status, res->body);
	}
	auto worker_address = res->body;
	StringUtil::Trim(worker_address);
	if (worker_address.empty()) {
		throw IOException("orchestrate(): orchestrator returned an empty worker address");
	}
	return worker_address;
}

static unique_ptr<TableRef> OrchestrateBind(ClientContext &context, TableFunctionBindInput &input) {
	if (input.inputs[0].IsNull() || input.inputs[1].IsNull() || input.inputs[2].IsNull()) {
		throw BinderException("orchestrate(): arguments cannot be NULL");
	}

	auto client_id = input.inputs[0].GetValue<string>();
	auto sql_query = input.inputs[1].GetValue<string>();
	auto orchestrator_address = input.inputs[2].GetValue<string>();

	auto worker_address = FetchWorkerAddress(orchestrator_address, client_id);

	auto rewritten = "SELECT * FROM rpc_call(" + KeywordHelper::WriteQuoted(worker_address, '\'') + ", " +
	                 KeywordHelper::WriteQuoted(sql_query, '\'') + ")";

	Parser parser(context.GetParserOptions());
	parser.ParseQuery(rewritten);

	if (parser.statements.size() != 1 || parser.statements[0]->type != StatementType::SELECT_STATEMENT) {
		throw InternalException("orchestrate(): failed to construct rpc_call query");
	}

	auto select = unique_ptr_cast<SQLStatement, SelectStatement>(std::move(parser.statements[0]));
	return make_uniq<SubqueryRef>(std::move(select));
}

//===--------------------------------------------------------------------===//
// Registration
//===--------------------------------------------------------------------===//

void OrchestrateTableFunction::RegisterFunction(BuiltinFunctions &set) {
	TableFunction func("orchestrate", {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR}, nullptr,
	                   nullptr);
	func.bind_replace = OrchestrateBind;
	set.AddFunction(func);
}

} // namespace duckdb

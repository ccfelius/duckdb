#include "duckdb_node.hpp"
#include <thread>

namespace node_duckdb {

Napi::FunctionReference Connection::constructor;

Napi::Object Connection::Init(Napi::Env env, Napi::Object exports) {
	Napi::HandleScope scope(env);

	Napi::Function t =
	    DefineClass(env, "Connection",
	                {InstanceMethod("prepare", &Connection::Prepare), InstanceMethod("exec", &Connection::Exec), InstanceMethod("register", &Connection::Register)});

	constructor = Napi::Persistent(t);
	constructor.SuppressDestruct();

	exports.Set("Connection", t);
	return exports;
}

struct ConnectTask : public Task {
	ConnectTask(Connection &connection_, Napi::Function callback_) : Task(connection_, callback_) {
	}

	void DoWork() override {
		auto &connection = Get<Connection>();
		connection.connection = duckdb::make_unique<duckdb::Connection>(*connection.database_ref->database);
	}
};

Connection::Connection(const Napi::CallbackInfo &info) : Napi::ObjectWrap<Connection>(info) {
	Napi::Env env = info.Env();
	int length = info.Length();

	if (length <= 0 || !Database::HasInstance(info[0])) {
		Napi::TypeError::New(env, "Database object expected").ThrowAsJavaScriptException();
		return;
	}

	database_ref = Napi::ObjectWrap<Database>::Unwrap(info[0].As<Napi::Object>());
	database_ref->Ref();

	Napi::Function callback;
	if (info.Length() > 0 && info[1].IsFunction()) {
		callback = info[1].As<Napi::Function>();
	}

	database_ref->Schedule(env, duckdb::make_unique<ConnectTask>(*this, callback));
}

Connection::~Connection() {
	database_ref->Unref();
	database_ref = nullptr;
	for (auto& fun : udfs) {
		fun.Release();
	}
}

Napi::Value Connection::Prepare(const Napi::CallbackInfo &info) {
	std::vector<napi_value> args;
	// push the connection as first argument
	args.push_back(Value());
	// we need to pass all the arguments onward to statement
	for (size_t i = 0; i < info.Length(); i++) {
		args.push_back(info[i]);
	}
	auto res = Utils::NewUnwrap<Statement>(args);
	res->SetProcessFirstParam();
	return res->Value();
}


static Napi::ThreadSafeFunction fun;

struct JSArgs {
	JSArgs(duckdb::DataChunk& args_p, duckdb::Vector& result_p) : args(args_p), result(result_p) {}

	duckdb::DataChunk &args;
	duckdb::Vector &result;
};


struct RegisterTask : public Task {
	RegisterTask(Connection &connection_, std::string name_, Napi::Function callback_)
	    : Task(connection_, callback_), name(name_)  {
	}

	void DoWork() override {
		auto &connection = Get<Connection>();
		duckdb::scalar_function_t udf_function = [&](duckdb::DataChunk &args, duckdb::ExpressionState &state, duckdb::Vector &result) -> void {
			auto jsargs = new JSArgs(args, result);
			bool done = false;

			auto arg_data = jsargs->args.Orrify();

			auto callback = [&](Napi::Env env, Napi::Function jsCallback, void* data = nullptr) -> void {
				auto jsargs = (JSArgs*) data;
				for (idx_t i = 0; i < jsargs->args.size(); i++) {
					auto real_i = arg_data[0].sel->get_index(i);
					auto val = ((int*) arg_data[0].data)[real_i];
					auto call_res = jsCallback.Call({Napi::Number::New(env, val)});
					result.SetValue(i, duckdb::Value::INTEGER(call_res.ToNumber().Int32Value())) ;
				}
				done = true;
			};

			fun.BlockingCall(jsargs, callback);
			while (!done) {
				std::this_thread::yield();
			}
			// TODO this is wrong
			//fun.Release();
		};

		duckdb::ScalarFunction function({duckdb::LogicalType::INTEGER}, duckdb::LogicalType::INTEGER, udf_function);
		duckdb::CreateScalarFunctionInfo info(function);
		info.name = name;

		auto &con = *connection.connection;
		con.BeginTransaction();
		auto &context = *con.context;
		auto &catalog = duckdb::Catalog::GetCatalog(context);
		catalog.CreateFunction(context, &info);
		con.Commit();

	}
	std::string name;
	bool success;
};


Napi::Value Connection::Register(const Napi::CallbackInfo &info) {
	auto env = info.Env();
	if (info.Length() != 2 || !info[0].IsString() || !info[1].IsFunction()) {
		Napi::TypeError::New(env, "Holding it wrong").ThrowAsJavaScriptException();
		return env.Null();
	}

	std::string name = info[0].As<Napi::String>();
	Napi::Function udf = info[1].As<Napi::Function>();
	fun = Napi::ThreadSafeFunction::New(env, udf, name, 0, 1);
	database_ref->Schedule(info.Env(), duckdb::make_unique<RegisterTask>(*this, name, udf));

	return Value();
}

struct ExecTask : public Task {
	ExecTask(Connection &connection_, std::string sql_, Napi::Function callback_)
	    : Task(connection_, callback_), sql(sql_) {
	}

	void DoWork() override {
		auto &connection = Get<Connection>();

		success = true;
		auto statements = connection.connection->ExtractStatements(sql);
		if (statements.size() == 0) {
			return;
		}

		// thanks Mark
		for (duckdb::idx_t i = 0; i < statements.size(); i++) {
			auto res = connection.connection->Query(move(statements[i]));
			if (!res->success) {
				success = false;
				error = res->error;
				break;
			}
		}
	}
	std::string sql;
	bool success;
	std::string error;
};

Napi::Value Connection::Exec(const Napi::CallbackInfo &info) {
	auto env = info.Env();

	if (info.Length() < 1 || !info[0].IsString()) {
		Napi::TypeError::New(env, "SQL query expected").ThrowAsJavaScriptException();
		return env.Null();
	}

	std::string sql = info[0].As<Napi::String>();

	Napi::Function callback;
	if (info.Length() > 0 && info[1].IsFunction()) {
		callback = info[1].As<Napi::Function>();
	}

	database_ref->Schedule(info.Env(), duckdb::make_unique<ExecTask>(*this, sql, callback));
	return Value();
}

} // namespace node_duckdb

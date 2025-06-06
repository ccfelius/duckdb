#include "duckdb/logging/log_type.hpp"
#include "duckdb/logging/log_manager.hpp"
#include "duckdb/logging/log_storage.hpp"
#include "duckdb/logging/file_system_logger.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/client_data.hpp"

namespace duckdb {

unique_ptr<Logger> LogManager::CreateLogger(LoggingContext context, bool thread_safe, bool mutable_settings) {
	unique_lock<mutex> lck(lock);

	auto registered_logging_context = RegisterLoggingContextInternal(context);

	if (mutable_settings) {
		return make_uniq<MutableLogger>(config, registered_logging_context, *this);
	}
	if (!config.enabled) {
		return make_uniq<NopLogger>(*this);
	}
	if (!thread_safe) {
		// TODO: implement ThreadLocalLogger and return it here
	}
	return make_uniq<ThreadSafeLogger>(config, registered_logging_context, *this);
}

RegisteredLoggingContext LogManager::RegisterLoggingContext(LoggingContext &context) {
	unique_lock<mutex> lck(lock);

	return RegisterLoggingContextInternal(context);
}

bool LogManager::RegisterLogStorage(const string &name, shared_ptr<LogStorage> &storage) {
	if (registered_log_storages.find(name) != registered_log_storages.end()) {
		return false;
	}
	registered_log_storages.insert({name, std::move(storage)});
	return true;
}

Logger &LogManager::GlobalLogger() {
	return *global_logger;
}

shared_ptr<Logger> LogManager::GlobalLoggerReference() {
	return global_logger;
}

void LogManager::Flush() {
	unique_lock<mutex> lck(lock);
	log_storage->Flush();
}

shared_ptr<LogStorage> LogManager::GetLogStorage() {
	unique_lock<mutex> lck(lock);
	return log_storage;
}

bool LogManager::CanScan() {
	unique_lock<mutex> lck(lock);
	return log_storage->CanScan();
}

LogManager::LogManager(DatabaseInstance &db, LogConfig config_p) : config(std::move(config_p)) {
	log_storage = make_uniq<InMemoryLogStorage>(db);
}

LogManager::~LogManager() {
}

void LogManager::Initialize() {
	LoggingContext context(LogContextScope::DATABASE);
	global_logger = CreateLogger(context, true, true);

	RegisterDefaultLogTypes();
}

LogManager &LogManager::Get(ClientContext &context) {
	return context.db->GetLogManager();
}

RegisteredLoggingContext LogManager::RegisterLoggingContextInternal(LoggingContext &context) {
	RegisteredLoggingContext result = {next_registered_logging_context_index, context};

	next_registered_logging_context_index += 1;

	if (next_registered_logging_context_index == NumericLimits<idx_t>::Maximum()) {
		throw InternalException("Ran out of available log context ids.");
	}

	return result;
}

void LogManager::WriteLogEntry(timestamp_t timestamp, const char *log_type, LogLevel log_level, const char *log_message,
                               const RegisteredLoggingContext &context) {
	unique_lock<mutex> lck(lock);
	log_storage->WriteLogEntry(timestamp, log_level, log_type, log_message, context);
}

void LogManager::FlushCachedLogEntries(DataChunk &chunk, const RegisteredLoggingContext &context) {
	throw NotImplementedException("FlushCachedLogEntries");
}

void LogManager::SetEnableLogging(bool enable) {
	unique_lock<mutex> lck(lock);
	config.enabled = enable;
	global_logger->UpdateConfig(config);
}

void LogManager::SetLogMode(LogMode mode) {
	unique_lock<mutex> lck(lock);
	config.mode = mode;
	global_logger->UpdateConfig(config);
}

void LogManager::SetLogLevel(LogLevel level) {
	unique_lock<mutex> lck(lock);
	config.level = level;
	global_logger->UpdateConfig(config);
}

void LogManager::SetEnabledLogTypes(unordered_set<string> &enabled_log_types) {
	unique_lock<mutex> lck(lock);
	config.enabled_log_types = enabled_log_types;
	global_logger->UpdateConfig(config);
}

void LogManager::SetDisabledLogTypes(unordered_set<string> &disabled_log_types) {
	unique_lock<mutex> lck(lock);
	config.disabled_log_types = disabled_log_types;
	global_logger->UpdateConfig(config);
}

void LogManager::SetLogStorage(DatabaseInstance &db, const string &storage_name) {
	unique_lock<mutex> lck(lock);
	auto storage_name_to_lower = StringUtil::Lower(storage_name);

	if (config.storage == storage_name_to_lower) {
		return;
	}

	// Flush the old storage, we are going to replace it.
	log_storage->Flush();

	if (storage_name_to_lower == LogConfig::IN_MEMORY_STORAGE_NAME) {
		log_storage = make_shared_ptr<InMemoryLogStorage>(db);
	} else if (storage_name_to_lower == LogConfig::STDOUT_STORAGE_NAME) {
		log_storage = make_shared_ptr<StdOutLogStorage>();
	} else if (storage_name_to_lower == LogConfig::FILE_STORAGE_NAME) {
		throw NotImplementedException("File log storage is not yet implemented");
	} else if (registered_log_storages.find(storage_name_to_lower) != registered_log_storages.end()) {
		log_storage = registered_log_storages[storage_name_to_lower];
	} else {
		throw InvalidInputException("Log storage '%s' is not yet registered", storage_name);
	}
	config.storage = storage_name_to_lower;
}

void LogManager::SetEnableStructuredLoggers(vector<string> &enabled_logger_types) {
	unique_lock<mutex> lck(lock);
	config.enabled_log_types.clear();

	LogLevel min_log_level = LogLevel::LOG_FATAL;

	for (const auto &enabled_logger_type : enabled_logger_types) {
		auto lookup = LookupLogTypeInternal(enabled_logger_type);
		if (!lookup) {
			throw InvalidInputException("Unknown log type: '%s'", enabled_logger_type);
		}

		config.enabled_log_types.insert(enabled_logger_type);

		min_log_level = MinValue(min_log_level, lookup->level);
	}

	config.level = min_log_level;
	config.mode = LogMode::ENABLE_SELECTED;
	config.enabled = true;
}

void LogManager::TruncateLogStorage() {
	unique_lock<mutex> lck(lock);
	log_storage->Truncate();
}

LogConfig LogManager::GetConfig() {
	unique_lock<mutex> lck(lock);
	return config;
}

optional_ptr<const LogType> LogManager::LookupLogType(const string &type) {
	unique_lock<mutex> lck(lock);
	return LookupLogTypeInternal(type);
}

DUCKDB_API void RegisterDefaultLogTypes() {
}

optional_ptr<const LogType> LogManager::LookupLogTypeInternal(const string &type) {
	auto lookup = registered_log_types.find(type);
	if (lookup != registered_log_types.end()) {
		return *lookup->second;
	}
	return nullptr;
}

void LogManager::RegisterLogType(unique_ptr<LogType> type) {
	unique_lock<mutex> lck(lock);

	auto lookup = registered_log_types.find(type->name);
	if (lookup != registered_log_types.end()) {
		throw InvalidInputException("Registered log writer '%s' already exists", type->name);
	}

	registered_log_types[type->name] = std::move(type);
}

void LogManager::RegisterDefaultLogTypes() {
	RegisterLogType(make_uniq<DefaultLogType>());
	RegisterLogType(make_uniq<FileSystemLogType>());
	RegisterLogType(make_uniq<HTTPLogType>());
	RegisterLogType(make_uniq<QueryLogType>());
	RegisterLogType(make_uniq<PhysicalOperatorLogType>());
}

} // namespace duckdb

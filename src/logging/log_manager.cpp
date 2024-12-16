#include "duckdb/logging/log_manager.hpp"
#include "duckdb/logging/log_storage.hpp"

//#include "duckdb/common/types/column/column_data_collection.hpp"
//#include "duckdb/common/types/data_chunk.hpp"
//#include "duckdb/main/client_context.hpp"
//#include "duckdb/main/connection.hpp"
//#include "duckdb/main/database.hpp"
//#include "duckdb/main/table_description.hpp"
//
//#include <duckdb/common/file_opener.hpp>
//#include <duckdb/parallel/thread_context.hpp>

namespace duckdb {

unique_ptr<Logger> LogManager::CreateLogger(LoggingContext context, bool thread_safe, bool mutable_settings) {
	// Make a copy of the config holding the lock
	LogConfig config_copy;
	{
		unique_lock<mutex> lck(lock);
		config_copy = config;
	}

	if (mutable_settings) {
		return make_uniq<MutableLogger>(config_copy, context, *this);
	}
	if (!config_copy.enabled) {
		return make_uniq<NopLogger>(*this);
	}
	if (!thread_safe) {
		// TODO: implement ThreadLocalLogger and return it here
	}
	return make_uniq<ThreadSafeLogger>(config_copy, context, *this);
}

RegisteredLoggingContext LogManager::RegisterLoggingContext(LoggingContext &context) {
	unique_lock<mutex> lck(lock);

	RegisteredLoggingContext result = {next_registered_logging_context_index, context};

	next_registered_logging_context_index += 1;

	if (next_registered_logging_context_index == NumericLimits<idx_t>::Maximum()) {
		throw InternalException("Ran out of available log context ids.");
	}

	return result;
}

Logger &LogManager::GlobalLogger() {
	unique_lock<mutex> lck(lock);
	return *global_logger;
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

LogManager::LogManager(DatabaseInstance &db, LogConfig config_p) : config(config_p) {
	log_storage = make_uniq<InMemoryLogStorage>(db);
}

LogManager::~LogManager() {
}

void LogManager::Initialize() {
	LoggingContext context(LogContextScope::DATABASE);
	global_logger = CreateLogger(context, true, true);
}

LogManager &LogManager::Get(ClientContext &context) {
	return context.db->GetLogManager();
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

void LogManager::SetEnabledLoggers(unordered_set<string> &enabled_loggers) {
	unique_lock<mutex> lck(lock);
	config.enabled_loggers = enabled_loggers;
	global_logger->UpdateConfig(config);
}

void LogManager::SetDisabledLoggers(unordered_set<string> &disabled_loggers) {
	unique_lock<mutex> lck(lock);
	config.disabled_loggers = disabled_loggers;
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
		config.storage = storage_name_to_lower;
	} else if (storage_name_to_lower == LogConfig::STDOUT_STORAGE_NAME) {
		log_storage = make_shared_ptr<StdOutLogStorage>();
		config.storage = storage_name_to_lower;
	} else if (storage_name_to_lower == LogConfig::FILE_STORAGE_NAME) {
		throw NotImplementedException("File log storage is not yet implemented");
	}
}

LogConfig LogManager::GetConfig() {
	unique_lock<mutex> lck(lock);
	return config;
}

} // namespace duckdb

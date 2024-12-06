//===----------------------------------------------------------------------===//
//                         DuckDB
//
// duckdb/logging/log_storage.hpp
//
//
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb/logging/logger.hpp"

namespace duckdb {

// Holds global logging state
// - Handles configuration changes
// - Creates Loggers with cached configuration
// - Main sink for logs (either by logging directly into this, or by syncing a pre-cached set of log entries)
// - Holds the logs (in case of in-memory
class LogManager : public enable_shared_from_this<LogManager> {
	friend class ThreadSafeLogger;
	friend class ThreadLocalLogger;
	friend class MutableLogger;

public:
	// Note: two step initialization because Logger needs shared pointer to log manager TODO: can we clean up?
	explicit LogManager(shared_ptr<DatabaseInstance> &db, LogConfig config = LogConfig());
	~LogManager();
	void Initialize();

	static LogManager &Get(ClientContext &context);
	unique_ptr<Logger> CreateLogger(LoggingContext context, bool thread_safe = true, bool mutable_settings = false);

	RegisteredLoggingContext RegisterLoggingContext(LoggingContext &context);
	// TODO: never called yet
	void DropLoggingContext(RegisteredLoggingContext &logging_id);

	//! The global logger can be used whe
	Logger &GlobalLogger();

	unique_ptr<LogStorage> log_storage;

	void SetEnableLogging(bool enable);
	void SetLogMode(LogMode mode);
	void SetLogLevel(LogLevel level);
	void SetEnabledLoggers(unordered_set <string> &enabled_loggers);
	void SetDisabledLoggers(unordered_set <string> &disabled_loggers);
	void SetLogStorage(shared_ptr<DatabaseInstance> &db, const string &storage_name);

	LogConfig GetConfig();

protected:
	// This is to be called by the Loggers only, it does not verify log_level and log_type
	void WriteLogEntry(timestamp_t, const char *log_type, LogLevel log_level, const char *log_message,
	                   const RegisteredLoggingContext &context);
	// This allows efficiently pushing a cached set of log entries into the log manager
	void FlushCachedLogEntries(DataChunk &chunk, const RegisteredLoggingContext &context);

	mutex lock;
	LogConfig config;

	unique_ptr<Logger> global_logger;

	idx_t next_registered_logging_context_index = 0;

	// TOOD: this can be a set? Should we store at all?
	unordered_map<idx_t, LoggingContext> registered_log_contexts;
};

}
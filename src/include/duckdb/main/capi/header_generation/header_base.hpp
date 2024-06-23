//===----------------------------------------------------------------------===//
// WARNING
#error "This header should not be included directly, it's used to generated duckdb.h and duckdb.hpp"
//===----------------------------------------------------------------------===//

// Note: to modify DuckDB's CAPI, the codegen mechanism should be used

// DUCKDB_START_OF_HEADER

#pragma once

//! duplicate of duckdb/main/winapi.hpp
#ifndef DUCKDB_API
#ifdef _WIN32
#if defined(DUCKDB_BUILD_LIBRARY) && !defined(DUCKDB_BUILD_LOADABLE_EXTENSION)
#define DUCKDB_API __declspec(dllexport)
#else
#define DUCKDB_API __declspec(dllimport)
#endif
#else
#define DUCKDB_API
#endif
#endif

//! duplicate of duckdb/main/winapi.hpp
#ifndef DUCKDB_EXTENSION_API
#ifdef _WIN32
#ifdef DUCKDB_BUILD_LOADABLE_EXTENSION
#define DUCKDB_EXTENSION_API __declspec(dllexport)
#else
#define DUCKDB_EXTENSION_API
#endif
#else
#define DUCKDB_EXTENSION_API __attribute__((visibility("default")))
#endif
#endif

//! In the future, we are planning to move extension functions to a separate header. For now you can set the define
//! below to remove the functions that are planned to be moved out of this header.
// #define DUCKDB_NO_EXTENSION_FUNCTIONS

//! Set the define below to remove all functions that are deprecated or planned to be deprecated
// #define DUCKDB_API_NO_DEPRECATED

//! API versions
//! If no explicit API version is defined, the latest API version is used.
//! Note that using older API versions (i.e. not using DUCKDB_API_LATEST) is deprecated.
//! These will not be supported long-term, and will be removed in future versions.
#ifndef DUCKDB_API_0_3_1
#define DUCKDB_API_0_3_1 1
#endif
#ifndef DUCKDB_API_0_3_2
#define DUCKDB_API_0_3_2 2
#endif
#ifndef DUCKDB_API_LATEST
#define DUCKDB_API_LATEST DUCKDB_API_0_3_2
#endif

#ifndef DUCKDB_API_VERSION
#define DUCKDB_API_VERSION DUCKDB_API_LATEST
#endif

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

//===--------------------------------------------------------------------===//
// Enums
//===--------------------------------------------------------------------===//
// WARNING: the numbers of these enums should not be changed, as changing the numbers breaks ABI compatibility
// Always add enums at the END of the enum
//! An enum over DuckDB's internal types.
typedef enum DUCKDB_TYPE {
	DUCKDB_TYPE_INVALID = 0,
	// bool
	DUCKDB_TYPE_BOOLEAN = 1,
	// int8_t
	DUCKDB_TYPE_TINYINT = 2,
	// int16_t
	DUCKDB_TYPE_SMALLINT = 3,
	// int32_t
	DUCKDB_TYPE_INTEGER = 4,
	// int64_t
	DUCKDB_TYPE_BIGINT = 5,
	// uint8_t
	DUCKDB_TYPE_UTINYINT = 6,
	// uint16_t
	DUCKDB_TYPE_USMALLINT = 7,
	// uint32_t
	DUCKDB_TYPE_UINTEGER = 8,
	// uint64_t
	DUCKDB_TYPE_UBIGINT = 9,
	// float
	DUCKDB_TYPE_FLOAT = 10,
	// double
	DUCKDB_TYPE_DOUBLE = 11,
	// duckdb_timestamp, in microseconds
	DUCKDB_TYPE_TIMESTAMP = 12,
	// duckdb_date
	DUCKDB_TYPE_DATE = 13,
	// duckdb_time
	DUCKDB_TYPE_TIME = 14,
	// duckdb_interval
	DUCKDB_TYPE_INTERVAL = 15,
	// duckdb_hugeint
	DUCKDB_TYPE_HUGEINT = 16,
	// duckdb_uhugeint
	DUCKDB_TYPE_UHUGEINT = 32,
	// const char*
	DUCKDB_TYPE_VARCHAR = 17,
	// duckdb_blob
	DUCKDB_TYPE_BLOB = 18,
	// decimal
	DUCKDB_TYPE_DECIMAL = 19,
	// duckdb_timestamp, in seconds
	DUCKDB_TYPE_TIMESTAMP_S = 20,
	// duckdb_timestamp, in milliseconds
	DUCKDB_TYPE_TIMESTAMP_MS = 21,
	// duckdb_timestamp, in nanoseconds
	DUCKDB_TYPE_TIMESTAMP_NS = 22,
	// enum type, only useful as logical type
	DUCKDB_TYPE_ENUM = 23,
	// list type, only useful as logical type
	DUCKDB_TYPE_LIST = 24,
	// struct type, only useful as logical type
	DUCKDB_TYPE_STRUCT = 25,
	// map type, only useful as logical type
	DUCKDB_TYPE_MAP = 26,
	// duckdb_array, only useful as logical type
	DUCKDB_TYPE_ARRAY = 33,
	// duckdb_hugeint
	DUCKDB_TYPE_UUID = 27,
	// union type, only useful as logical type
	DUCKDB_TYPE_UNION = 28,
	// duckdb_bit
	DUCKDB_TYPE_BIT = 29,
	// duckdb_time_tz
	DUCKDB_TYPE_TIME_TZ = 30,
	// duckdb_timestamp
	DUCKDB_TYPE_TIMESTAMP_TZ = 31,
} duckdb_type;
//! An enum over the returned state of different functions.
typedef enum { DuckDBSuccess = 0, DuckDBError = 1 } duckdb_state;
//! An enum over the pending state of a pending query result.
typedef enum {
	DUCKDB_PENDING_RESULT_READY = 0,
	DUCKDB_PENDING_RESULT_NOT_READY = 1,
	DUCKDB_PENDING_ERROR = 2,
	DUCKDB_PENDING_NO_TASKS_AVAILABLE = 3
} duckdb_pending_state;
//! An enum over DuckDB's different result types.
typedef enum {
	DUCKDB_RESULT_TYPE_INVALID = 0,
	DUCKDB_RESULT_TYPE_CHANGED_ROWS = 1,
	DUCKDB_RESULT_TYPE_NOTHING = 2,
	DUCKDB_RESULT_TYPE_QUERY_RESULT = 3,
} duckdb_result_type;
//! An enum over DuckDB's different statement types.
typedef enum {
	DUCKDB_STATEMENT_TYPE_INVALID = 0,
	DUCKDB_STATEMENT_TYPE_SELECT = 1,
	DUCKDB_STATEMENT_TYPE_INSERT = 2,
	DUCKDB_STATEMENT_TYPE_UPDATE = 3,
	DUCKDB_STATEMENT_TYPE_EXPLAIN = 4,
	DUCKDB_STATEMENT_TYPE_DELETE = 5,
	DUCKDB_STATEMENT_TYPE_PREPARE = 6,
	DUCKDB_STATEMENT_TYPE_CREATE = 7,
	DUCKDB_STATEMENT_TYPE_EXECUTE = 8,
	DUCKDB_STATEMENT_TYPE_ALTER = 9,
	DUCKDB_STATEMENT_TYPE_TRANSACTION = 10,
	DUCKDB_STATEMENT_TYPE_COPY = 11,
	DUCKDB_STATEMENT_TYPE_ANALYZE = 12,
	DUCKDB_STATEMENT_TYPE_VARIABLE_SET = 13,
	DUCKDB_STATEMENT_TYPE_CREATE_FUNC = 14,
	DUCKDB_STATEMENT_TYPE_DROP = 15,
	DUCKDB_STATEMENT_TYPE_EXPORT = 16,
	DUCKDB_STATEMENT_TYPE_PRAGMA = 17,
	DUCKDB_STATEMENT_TYPE_VACUUM = 18,
	DUCKDB_STATEMENT_TYPE_CALL = 19,
	DUCKDB_STATEMENT_TYPE_SET = 20,
	DUCKDB_STATEMENT_TYPE_LOAD = 21,
	DUCKDB_STATEMENT_TYPE_RELATION = 22,
	DUCKDB_STATEMENT_TYPE_EXTENSION = 23,
	DUCKDB_STATEMENT_TYPE_LOGICAL_PLAN = 24,
	DUCKDB_STATEMENT_TYPE_ATTACH = 25,
	DUCKDB_STATEMENT_TYPE_DETACH = 26,
	DUCKDB_STATEMENT_TYPE_MULTI = 27,
} duckdb_statement_type;

//===--------------------------------------------------------------------===//
// General type definitions
//===--------------------------------------------------------------------===//

//! DuckDB's index type.
typedef uint64_t idx_t;

//! The callback that will be called to destroy data, e.g.,
//! bind data (if any), init data (if any), extra data for replacement scans (if any)
typedef void (*duckdb_delete_callback_t)(void *data);

//! Used for threading, contains a task state. Must be destroyed with `duckdb_destroy_state`.
typedef void *duckdb_task_state;

//===--------------------------------------------------------------------===//
// Types (no explicit freeing)
//===--------------------------------------------------------------------===//

//! Days are stored as days since 1970-01-01
//! Use the duckdb_from_date/duckdb_to_date function to extract individual information
typedef struct {
	int32_t days;
} duckdb_date;
typedef struct {
	int32_t year;
	int8_t month;
	int8_t day;
} duckdb_date_struct;

//! Time is stored as microseconds since 00:00:00
//! Use the duckdb_from_time/duckdb_to_time function to extract individual information
typedef struct {
	int64_t micros;
} duckdb_time;
typedef struct {
	int8_t hour;
	int8_t min;
	int8_t sec;
	int32_t micros;
} duckdb_time_struct;

//! TIME_TZ is stored as 40 bits for int64_t micros, and 24 bits for int32_t offset
typedef struct {
	uint64_t bits;
} duckdb_time_tz;
typedef struct {
	duckdb_time_struct time;
	int32_t offset;
} duckdb_time_tz_struct;

//! Timestamps are stored as microseconds since 1970-01-01
//! Use the duckdb_from_timestamp/duckdb_to_timestamp function to extract individual information
typedef struct {
	int64_t micros;
} duckdb_timestamp;
typedef struct {
	duckdb_date_struct date;
	duckdb_time_struct time;
} duckdb_timestamp_struct;
typedef struct {
	int32_t months;
	int32_t days;
	int64_t micros;
} duckdb_interval;

//! Hugeints are composed of a (lower, upper) component
//! The value of the hugeint is upper * 2^64 + lower
//! For easy usage, the functions duckdb_hugeint_to_double/duckdb_double_to_hugeint are recommended
typedef struct {
	uint64_t lower;
	int64_t upper;
} duckdb_hugeint;
typedef struct {
	uint64_t lower;
	uint64_t upper;
} duckdb_uhugeint;

//! Decimals are composed of a width and a scale, and are stored in a hugeint
typedef struct {
	uint8_t width;
	uint8_t scale;
	duckdb_hugeint value;
} duckdb_decimal;

//! A type holding information about the query execution progress
typedef struct {
	double percentage;
	uint64_t rows_processed;
	uint64_t total_rows_to_process;
} duckdb_query_progress_type;

//! The internal representation of a VARCHAR (string_t). If the VARCHAR does not
//! exceed 12 characters, then we inline it. Otherwise, we inline a prefix for faster
//! string comparisons and store a pointer to the remaining characters. This is a non-
//! owning structure, i.e., it does not have to be freed.
typedef struct {
	union {
		struct {
			uint32_t length;
			char prefix[4];
			char *ptr;
		} pointer;
		struct {
			uint32_t length;
			char inlined[12];
		} inlined;
	} value;
} duckdb_string_t;

//! The internal representation of a list metadata entry contains the list's offset in
//! the child vector, and its length. The parent vector holds these metadata entries,
//! whereas the child vector holds the data
typedef struct {
	uint64_t offset;
	uint64_t length;
} duckdb_list_entry;

//! A column consists of a pointer to its internal data. Don't operate on this type directly.
//! Instead, use functions such as duckdb_column_data, duckdb_nullmask_data,
//! duckdb_column_type, and duckdb_column_name, which take the result and the column index
//! as their parameters
typedef struct {
#if DUCKDB_API_VERSION < DUCKDB_API_0_3_2
	void *data;
	bool *nullmask;
	duckdb_type type;
	char *name;
#else
	// deprecated, use duckdb_column_data
	void *__deprecated_data;
	// deprecated, use duckdb_nullmask_data
	bool *__deprecated_nullmask;
	// deprecated, use duckdb_column_type
	duckdb_type __deprecated_type;
	// deprecated, use duckdb_column_name
	char *__deprecated_name;
#endif
	void *internal_data;
} duckdb_column;

//! A vector to a specified column in a data chunk. Lives as long as the
//! data chunk lives, i.e., must not be destroyed.
typedef struct _duckdb_vector {
	void *__vctr;
} * duckdb_vector;

//===--------------------------------------------------------------------===//
// Types (explicit freeing/destroying)
//===--------------------------------------------------------------------===//

//! Strings are composed of a char pointer and a size. You must free string.data
//! with `duckdb_free`.
typedef struct {
	char *data;
	idx_t size;
} duckdb_string;

//! BLOBs are composed of a byte pointer and a size. You must free blob.data
//! with `duckdb_free`.
typedef struct {
	void *data;
	idx_t size;
} duckdb_blob;

//! A query result consists of a pointer to its internal data.
//! Must be freed with 'duckdb_destroy_result'.
typedef struct {
#if DUCKDB_API_VERSION < DUCKDB_API_0_3_2
	idx_t column_count;
	idx_t row_count;
	idx_t rows_changed;
	duckdb_column *columns;
	char *error_message;
#else
	// deprecated, use duckdb_column_count
	idx_t __deprecated_column_count;
	// deprecated, use duckdb_row_count
	idx_t __deprecated_row_count;
	// deprecated, use duckdb_rows_changed
	idx_t __deprecated_rows_changed;
	// deprecated, use duckdb_column_*-family of functions
	duckdb_column *__deprecated_columns;
	// deprecated, use duckdb_result_error
	char *__deprecated_error_message;
#endif
	void *internal_data;
} duckdb_result;

//! A database object. Should be closed with `duckdb_close`.
typedef struct _duckdb_database {
	void *__db;
} * duckdb_database;

//! A connection to a duckdb database. Must be closed with `duckdb_disconnect`.
typedef struct _duckdb_connection {
	void *__conn;
} * duckdb_connection;

//! A prepared statement is a parameterized query that allows you to bind parameters to it.
//! Must be destroyed with `duckdb_destroy_prepare`.
typedef struct _duckdb_prepared_statement {
	void *__prep;
} * duckdb_prepared_statement;

//! Extracted statements. Must be destroyed with `duckdb_destroy_extracted`.
typedef struct _duckdb_extracted_statements {
	void *__extrac;
} * duckdb_extracted_statements;

//! The pending result represents an intermediate structure for a query that is not yet fully executed.
//! Must be destroyed with `duckdb_destroy_pending`.
typedef struct _duckdb_pending_result {
	void *__pend;
} * duckdb_pending_result;

//! The appender enables fast data loading into DuckDB.
//! Must be destroyed with `duckdb_appender_destroy`.
typedef struct _duckdb_appender {
	void *__appn;
} * duckdb_appender;

//! Can be used to provide start-up options for the DuckDB instance.
//! Must be destroyed with `duckdb_destroy_config`.
typedef struct _duckdb_config {
	void *__cnfg;
} * duckdb_config;

//! Holds an internal logical type.
//! Must be destroyed with `duckdb_destroy_logical_type`.
typedef struct _duckdb_logical_type {
	void *__lglt;
} * duckdb_logical_type;

//! Contains a data chunk from a duckdb_result.
//! Must be destroyed with `duckdb_destroy_data_chunk`.
typedef struct _duckdb_data_chunk {
	void *__dtck;
} * duckdb_data_chunk;

//! Holds a DuckDB value, which wraps a type.
//! Must be destroyed with `duckdb_destroy_value`.
typedef struct _duckdb_value {
	void *__val;
} * duckdb_value;

//===--------------------------------------------------------------------===//
// Function types
//===--------------------------------------------------------------------===//
//! Additional function info. When setting this info, it is necessary to pass a destroy-callback function.
typedef struct _duckdb_function_info {
	void *__val;
} * duckdb_function_info;

//===--------------------------------------------------------------------===//
// Scalar function types
//===--------------------------------------------------------------------===//
//! A scalar function. Must be destroyed with `duckdb_destroy_scalar_function`.
typedef struct _duckdb_scalar_function {
	void *__val;
} * duckdb_scalar_function;

//! The main function of the scalar function.
typedef void (*duckdb_scalar_function_t)(duckdb_function_info info, duckdb_data_chunk input, duckdb_vector output);

//===--------------------------------------------------------------------===//
// Table function types
//===--------------------------------------------------------------------===//

#ifndef DUCKDB_NO_EXTENSION_FUNCTIONS
//! A table function. Must be destroyed with `duckdb_destroy_table_function`.
typedef struct _duckdb_table_function {
	void *__val;
} * duckdb_table_function;

//! The bind info of the function. When setting this info, it is necessary to pass a destroy-callback function.
typedef struct _duckdb_bind_info {
	void *__val;
} * duckdb_bind_info;

//! Additional function init info. When setting this info, it is necessary to pass a destroy-callback function.
typedef struct _duckdb_init_info {
	void *__val;
} * duckdb_init_info;

//! The bind function of the table function.
typedef void (*duckdb_table_function_bind_t)(duckdb_bind_info info);

//! The (possibly thread-local) init function of the table function.
typedef void (*duckdb_table_function_init_t)(duckdb_init_info info);

//! The main function of the table function.
typedef void (*duckdb_table_function_t)(duckdb_function_info info, duckdb_data_chunk output);

//===--------------------------------------------------------------------===//
// Replacement scan types
//===--------------------------------------------------------------------===//

//! Additional replacement scan info. When setting this info, it is necessary to pass a destroy-callback function.
typedef struct _duckdb_replacement_scan_info {
	void *__val;
} * duckdb_replacement_scan_info;

//! A replacement scan function that can be added to a database.
typedef void (*duckdb_replacement_callback_t)(duckdb_replacement_scan_info info, const char *table_name, void *data);
#endif

//===--------------------------------------------------------------------===//
// Arrow-related types
//===--------------------------------------------------------------------===//

//! Holds an arrow query result. Must be destroyed with `duckdb_destroy_arrow`.
typedef struct _duckdb_arrow {
	void *__arrw;
} * duckdb_arrow;

//! Holds an arrow array stream. Must be destroyed with `duckdb_destroy_arrow_stream`.
typedef struct _duckdb_arrow_stream {
	void *__arrwstr;
} * duckdb_arrow_stream;

//! Holds an arrow schema. Remember to release the respective ArrowSchema object.
typedef struct _duckdb_arrow_schema {
	void *__arrs;
} * duckdb_arrow_schema;

//! Holds an arrow array. Remember to release the respective ArrowArray object.
typedef struct _duckdb_arrow_array {
	void *__arra;
} * duckdb_arrow_array;

// DUCKDB_FUNCTIONS_ARE_GENERATED_HERE

#ifdef __cplusplus
}
#endif

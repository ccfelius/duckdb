//===----------------------------------------------------------------------===//
//                         DuckDB
//
// json_scan.hpp
//
//
//===----------------------------------------------------------------------===//

#pragma once

#include "buffered_json_reader.hpp"
#include "duckdb/common/multi_file_reader.hpp"
#include "duckdb/common/mutex.hpp"
#include "duckdb/common/pair.hpp"
#include "duckdb/common/types/type_map.hpp"
#include "duckdb/function/scalar/strftime_format.hpp"
#include "duckdb/function/table_function.hpp"
#include "json_enums.hpp"
#include "json_transform.hpp"
#include "json_reader_options.hpp"

namespace duckdb {

struct JSONScanData : public TableFunctionData {
public:
	JSONScanData();

	void InitializeReaders(ClientContext &context, MultiFileBindData &bind_data);
	void InitializeFormats();
	void InitializeFormats(bool auto_detect);

public:
	//! JSON reader options
	JSONReaderOptions options;

	//! The set of keys to extract (case sensitive)
	vector<string> key_names;

	//! The date format map
	unique_ptr<DateFormatMap> date_format_map;
	//! Options when transforming the JSON to columnar data
	JSONTransformOptions transform_options;

	//! The inferred avg tuple size
	idx_t avg_tuple_size = 420;
};

struct JSONScanInfo : public TableFunctionInfo {
public:
	explicit JSONScanInfo(JSONScanType type_p = JSONScanType::INVALID, JSONFormat format_p = JSONFormat::AUTO_DETECT,
	                      JSONRecordType record_type_p = JSONRecordType::AUTO_DETECT, bool auto_detect_p = false)
	    : type(type_p), format(format_p), record_type(record_type_p), auto_detect(auto_detect_p) {
	}

	JSONScanType type;
	JSONFormat format;
	JSONRecordType record_type;
	bool auto_detect;
};

struct JSONScanGlobalState {
public:
	JSONScanGlobalState(ClientContext &context, const MultiFileBindData &bind_data);

public:
	//! Bound data
	const MultiFileBindData &bind_data;
	const JSONScanData &json_data;
	//! Options when transforming the JSON to columnar data
	JSONTransformOptions transform_options;

	//! Column names that we're actually reading (after projection pushdown)
	vector<string> names;
	vector<column_t> column_ids;
	vector<ColumnIndex> column_indices;

	//! Buffer manager allocator
	Allocator &allocator;
	//! The current buffer capacity
	idx_t buffer_capacity;

	mutex lock;
	//! One JSON reader per file
	vector<optional_ptr<BufferedJSONReader>> json_readers;
	//! Current file/batch index
	atomic<idx_t> file_index;
	atomic<idx_t> batch_index;

	//! Current number of threads active
	idx_t system_threads;
	//! Whether we enable parallel scans (only if less files than threads)
	bool enable_parallel_scans;

	bool file_is_assigned = false;
	bool initialized = false;
};

struct JSONScanLocalState {
public:
	JSONScanLocalState(ClientContext &context, JSONScanGlobalState &gstate);

public:
	idx_t Read(JSONScanGlobalState &gstate);
	bool NextBuffer(JSONScanGlobalState &gstate);
	idx_t ReadNext(JSONScanGlobalState &gstate);
	void ThrowTransformError(idx_t object_index, const string &error_message);

	const MultiFileReaderData &GetReaderData() const;

	JSONReaderScanState &GetScanState() {
		return scan_state;
	}

	const JSONReaderScanState &GetScanState() const {
		return scan_state;
	}

public:
	//! Options when transforming the JSON to columnar data
	JSONTransformOptions transform_options;

	//! For determining average tuple size
	idx_t total_read_size;
	idx_t total_tuple_count;

private:
	bool ReadNextBuffer(JSONScanGlobalState &gstate);
	void ParseNextChunk(JSONScanGlobalState &gstate);

	void ParseJSON(char *const json_start, const idx_t json_size, const idx_t remaining);

	//! Must hold the lock
	bool TryInitializeScan(JSONScanGlobalState &gstate, JSONReaderScanState &scan_state, BufferedJSONReader &reader);
	void PrepareReader(JSONScanGlobalState &gstate, JSONReaderScanState &scan_state, BufferedJSONReader &reader);
	void TryIncrementFileIndex(JSONScanGlobalState &gstate) const;
	bool IsParallel(JSONScanGlobalState &gstate) const;

private:
	//! Scan state
	JSONReaderScanState scan_state;
};

struct JSONGlobalTableFunctionState : public GlobalTableFunctionState {
public:
	JSONGlobalTableFunctionState(ClientContext &context, TableFunctionInitInput &input);
	static unique_ptr<GlobalTableFunctionState> Init(ClientContext &context, TableFunctionInitInput &input);
	idx_t MaxThreads() const override;

public:
	JSONScanGlobalState state;
};

struct JSONLocalTableFunctionState : public LocalTableFunctionState {
public:
	JSONLocalTableFunctionState(ClientContext &context, JSONScanGlobalState &gstate);
	static unique_ptr<LocalTableFunctionState> Init(ExecutionContext &context, TableFunctionInitInput &input,
	                                                GlobalTableFunctionState *global_state);
	idx_t GetBatchIndex() const;

public:
	JSONScanLocalState state;
};

struct JSONScan {
public:
	static void AutoDetect(ClientContext &context, MultiFileBindData &bind_data, vector<LogicalType> &return_types,
	                       vector<string> &names);

	static double ScanProgress(ClientContext &context, const FunctionData *bind_data_p,
	                           const GlobalTableFunctionState *global_state);
	static OperatorPartitionData GetPartitionData(ClientContext &context, TableFunctionGetPartitionInput &input);
	static unique_ptr<NodeStatistics> Cardinality(ClientContext &context, const FunctionData *bind_data);

	static void Serialize(Serializer &serializer, const optional_ptr<FunctionData> bind_data,
	                      const TableFunction &function);
	static unique_ptr<FunctionData> Deserialize(Deserializer &deserializer, TableFunction &function);

	static void TableFunctionDefaults(TableFunction &table_function);
};

} // namespace duckdb

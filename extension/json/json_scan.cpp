#include "json_scan.hpp"

#include "duckdb/common/enum_util.hpp"
#include "duckdb/common/multi_file_reader.hpp"
#include "duckdb/common/serializer/deserializer.hpp"
#include "duckdb/common/serializer/serializer.hpp"
#include "duckdb/main/extension_helper.hpp"
#include "duckdb/parallel/task_scheduler.hpp"
#include "duckdb/storage/buffer_manager.hpp"
#include "json_multi_file_info.hpp"

namespace duckdb {

JSONScanData::JSONScanData() {
}

void JSONScanData::InitializeFormats() {
	InitializeFormats(options.auto_detect);
}

void JSONScanData::InitializeFormats(bool auto_detect_p) {
	type_id_map_t<vector<StrpTimeFormat>> candidate_formats;
	// Initialize date_format_map if anything was specified
	if (!options.date_format.empty()) {
		DateFormatMap::AddFormat(candidate_formats, LogicalTypeId::DATE, options.date_format);
	}
	if (!options.timestamp_format.empty()) {
		DateFormatMap::AddFormat(candidate_formats, LogicalTypeId::TIMESTAMP, options.timestamp_format);
	}

	if (auto_detect_p) {
		static const type_id_map_t<vector<const char *>> FORMAT_TEMPLATES = {
		    {LogicalTypeId::DATE, {"%m-%d-%Y", "%m-%d-%y", "%d-%m-%Y", "%d-%m-%y", "%Y-%m-%d", "%y-%m-%d"}},
		    {LogicalTypeId::TIMESTAMP,
		     {"%Y-%m-%d %H:%M:%S.%f", "%m-%d-%Y %I:%M:%S %p", "%m-%d-%y %I:%M:%S %p", "%d-%m-%Y %H:%M:%S",
		      "%d-%m-%y %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%SZ"}},
		};

		// Populate possible date/timestamp formats, assume this is consistent across columns
		for (auto &kv : FORMAT_TEMPLATES) {
			const auto &logical_type = kv.first;
			if (DateFormatMap::HasFormats(candidate_formats, logical_type)) {
				continue; // Already populated
			}
			const auto &format_strings = kv.second;
			for (auto &format_string : format_strings) {
				DateFormatMap::AddFormat(candidate_formats, logical_type, format_string);
			}
		}
	}
	date_format_map = make_uniq<DateFormatMap>(std::move(candidate_formats));
}

JSONScanGlobalState::JSONScanGlobalState(ClientContext &context, const MultiFileBindData &bind_data_p)
    : bind_data(bind_data_p), json_data(bind_data.bind_data->Cast<JSONScanData>()),
      transform_options(json_data.transform_options), allocator(BufferAllocator::Get(context)),
      buffer_capacity(json_data.options.maximum_object_size * 2),
      system_threads(TaskScheduler::GetScheduler(context).NumberOfThreads()),
      enable_parallel_scans(bind_data.file_list->GetTotalFileCount() < system_threads) {
}

JSONScanLocalState::JSONScanLocalState(ClientContext &context, JSONScanGlobalState &gstate)
    : scan_state(context, gstate.allocator, gstate.buffer_capacity) {
}

JSONGlobalTableFunctionState::JSONGlobalTableFunctionState(ClientContext &context, const MultiFileBindData &bind_data)
    : state(context, bind_data) {
}

unique_ptr<GlobalTableFunctionState> JSONGlobalTableFunctionState::Init(ClientContext &context,
                                                                        TableFunctionInitInput &input) {
	auto &bind_data = input.bind_data->Cast<MultiFileBindData>();
	auto &json_data = bind_data.bind_data->Cast<JSONScanData>();
	auto result = make_uniq<MultiFileGlobalState>(*bind_data.file_list);
	auto json_state = make_uniq<JSONGlobalTableFunctionState>(context, bind_data);
	auto &gstate = json_state->state;
	result->global_state = std::move(json_state);

	// Perform projection pushdown
	for (idx_t col_idx = 0; col_idx < input.column_ids.size(); col_idx++) {
		const auto &col_id = input.column_ids[col_idx];

		// Skip any multi-file reader / row id stuff
		if (col_id == bind_data.reader_bind.filename_idx || IsVirtualColumn(col_id)) {
			continue;
		}
		bool skip = false;
		for (const auto &hive_partitioning_index : bind_data.reader_bind.hive_partitioning_indexes) {
			if (col_id == hive_partitioning_index.index) {
				skip = true;
				break;
			}
		}
		if (skip) {
			continue;
		}

		gstate.names.push_back(json_data.key_names[col_id]);
		gstate.column_ids.push_back(col_idx);
		gstate.column_indices.push_back(input.column_indexes[col_idx]);
	}

	if (gstate.names.size() < json_data.key_names.size() || bind_data.file_options.union_by_name) {
		// If we are auto-detecting, but don't need all columns present in the file,
		// then we don't need to throw an error if we encounter an unseen column
		gstate.transform_options.error_unknown_key = false;
	}

	// Place readers where they belong
	vector<LogicalType> dummy_local_types(gstate.names.size(), LogicalType::ANY);
	vector<LogicalType> dummy_global_types(bind_data.names.size(), LogicalType::ANY);
	auto local_columns = MultiFileReaderColumnDefinition::ColumnsFromNamesAndTypes(gstate.names, dummy_local_types);
	auto global_columns =
	    MultiFileReaderColumnDefinition::ColumnsFromNamesAndTypes(bind_data.names, dummy_global_types);
	for (const auto &reader : bind_data.union_readers) {
		if (!reader->reader) {
			continue;
		}
		auto &union_reader = reader->reader->Cast<BufferedJSONReader>();
		union_reader.columns = global_columns;
		union_reader.Reset();
	}
	return std::move(result);
}

// idx_t JSONGlobalTableFunctionState::MaxThreads() const {
// 	auto &bind_data = state.json_data;
//
// 	if (!state.json_readers.empty() && state.json_readers[0]->HasFileHandle()) {
// 		// We opened and auto-detected a file, so we can get a better estimate
// 		auto &reader = *state.json_readers[0];
// 		if (bind_data.options.format == JSONFormat::NEWLINE_DELIMITED ||
// 		    reader.GetFormat() == JSONFormat::NEWLINE_DELIMITED) {
// 			return MaxValue<idx_t>(
// 			    state.json_readers[0]->GetFileHandle().FileSize() / bind_data.options.maximum_object_size, 1);
// 		}
// 	}
//
// 	if (bind_data.options.format == JSONFormat::NEWLINE_DELIMITED) {
// 		// We haven't opened any files, so this is our best bet
// 		return state.system_threads;
// 	}
//
// 	// One reader per file
// 	return state.bind_data.file_list->GetTotalFileCount();
// }

JSONLocalTableFunctionState::JSONLocalTableFunctionState(ClientContext &context, JSONScanGlobalState &gstate)
    : state(context, gstate) {
}

unique_ptr<LocalTableFunctionState> JSONLocalTableFunctionState::Init(ExecutionContext &context,
                                                                      TableFunctionInitInput &,
                                                                      GlobalTableFunctionState *global_state) {
	auto &gstate = global_state->Cast<JSONGlobalTableFunctionState>();
	auto result = make_uniq<JSONLocalTableFunctionState>(context.client, gstate.state);

	// Copy the transform options / date format map because we need to do thread-local stuff
	result->state.transform_options = gstate.state.transform_options;

	return std::move(result);
}

idx_t JSONLocalTableFunctionState::GetBatchIndex() const {
	return state.GetScanState().batch_index.GetIndex();
}

idx_t JSONScanLocalState::Read() {
	return scan_state.current_reader->Scan(scan_state);
}

// bool JSONScanLocalState::NextBuffer(JSONScanGlobalState &gstate) {
// 	if (scan_state.buffer_offset < scan_state.buffer_size) {
// 		throw InternalException("Not finished yet!?");
// 	}
// 	return ReadNextBuffer(gstate);
// }

// idx_t JSONScanLocalState::ReadNext(JSONScanGlobalState &gstate) {
// 	while (true) {
// 		if (scan_state.initialized) {
// 			auto count = Read();
// 			if (count > 0) {
// 				return count;
// 			}
// 		}
// 		scan_state.initialized = true;
// 		// exhausted buffer - read next
// 		if (!NextBuffer(gstate)) {
// 			// no buffer available - done
// 			return 0;
// 		}
// 	}
// }

void JSONScanLocalState::ParseJSON(char *const json_start, const idx_t json_size, const idx_t remaining) {
	scan_state.current_reader->ParseJSON(scan_state, json_start, json_size, remaining);
}

bool JSONScanLocalState::TryInitializeScan(JSONScanGlobalState &gstate, BufferedJSONReader &reader) {
	// try to initialize a scan in the given reader
	// three scenarios:
	// scenario 1 - unseekable file - Read from the file and setup the buffers
	// scenario 2 - seekable file - get the position from the file to read and return
	// scenario 3 - entire file readers - if we are reading an entire file at once, do not do anything here, except for
	// setting up the basics
	auto read_type = JSONFileReadType::SCAN_PARTIAL;
	if (!gstate.enable_parallel_scans || reader.GetFormat() != JSONFormat::NEWLINE_DELIMITED) {
		read_type = JSONFileReadType::SCAN_ENTIRE_FILE;
	}
	if (read_type == JSONFileReadType::SCAN_ENTIRE_FILE) {
		if (gstate.file_is_assigned) {
			return false;
		}
		gstate.file_is_assigned = true;
	}
	return reader.InitializeScan(scan_state, read_type);
}

void JSONScanLocalState::PrepareReader(JSONScanGlobalState &gstate, BufferedJSONReader &reader) {
	gstate.file_is_assigned = false;
	if (!gstate.enable_parallel_scans) {
		// we are reading the entire file - we don't even need to open the file yet
		return;
	}
	// prepare a reader for reading
	// scenario 1 & 2 -> auto detect
	// scenario 3 -> nothing
	reader.Initialize(gstate.allocator, gstate.buffer_capacity);
}

// bool JSONScanLocalState::ReadNextBuffer(JSONScanGlobalState &gstate) {
// 	// First we make sure we have a buffer to read into
//
// 	lock_guard<mutex> guard(gstate.lock);
// 	scan_state.ResetForNextBuffer();
// 	while (gstate.file_index < gstate.json_readers.size()) {
// 		if (gstate.initialized) {
// 			auto &current_file = *gstate.json_readers[gstate.file_index];
// 			if (TryInitializeScan(gstate, scan_state, current_file)) {
// 				// read from the current file yay
// 				scan_state.batch_index = gstate.batch_index++;
// 				return true;
// 			}
// 			// we could not read from the current file, move to the next file
// 			++gstate.file_index;
// 		} else {
// 			gstate.initialized = true;
// 		}
// 		if (gstate.file_index == gstate.json_readers.size()) {
// 			return false; // No more files left
// 		}
// 		// prepare the reader so we can read from it
// 		PrepareReader(gstate, *gstate.json_readers[gstate.file_index]);
// 	}
// 	return false;
// }

const MultiFileReaderData &JSONScanLocalState::GetReaderData() const {
	return scan_state.current_reader->reader_data;
}

void JSONScanLocalState::ThrowTransformError(idx_t object_index, const string &error_message) {
	scan_state.current_reader->ThrowTransformError(scan_state, object_index, error_message);
}

// double JSONScan::ScanProgress(ClientContext &, const FunctionData *, const GlobalTableFunctionState *global_state) {
// 	auto &gstate = global_state->Cast<JSONGlobalTableFunctionState>().state;
// 	double progress = 0;
// 	for (auto &reader : gstate.json_readers) {
// 		progress += reader->GetProgress();
// 	}
// 	return progress / double(gstate.json_readers.size());
// }

// OperatorPartitionData JSONScan::GetPartitionData(ClientContext &, TableFunctionGetPartitionInput &input) {
// 	if (input.partition_info.RequiresPartitionColumns()) {
// 		throw InternalException("JSONScan::GetPartitionData: partition columns not supported");
// 	}
// 	auto &lstate = input.local_state->Cast<JSONLocalTableFunctionState>();
// 	return OperatorPartitionData(lstate.GetBatchIndex());
// }
//
// unique_ptr<NodeStatistics> JSONScan::Cardinality(ClientContext &, const FunctionData *bind_data) {
// 	auto &data = bind_data->Cast<MultiFileBindData>();
// 	auto &json_data = data.bind_data->Cast<JSONScanData>();
// 	idx_t per_file_cardinality;
//
// 	per_file_cardinality = 42; // The cardinality of an unknown JSON file is the almighty number 42
// 	if (data.initial_reader) {
// 		auto &initial_reader = data.initial_reader->Cast<BufferedJSONReader>();
// 		if (initial_reader.HasFileHandle()) {
// 			per_file_cardinality = initial_reader.GetFileHandle().FileSize() / json_data.avg_tuple_size;
// 		}
// 	} else {
// 	}
// 	return make_uniq<NodeStatistics>(per_file_cardinality * data.file_list->GetTotalFileCount());
// }

void JSONScan::Serialize(Serializer &serializer, const optional_ptr<FunctionData> bind_data_p, const TableFunction &) {
	throw NotImplementedException("JSONScan Serialize not implemented");
}

unique_ptr<FunctionData> JSONScan::Deserialize(Deserializer &deserializer, TableFunction &) {
	throw NotImplementedException("JSONScan Deserialize not implemented");
}

void JSONScan::TableFunctionDefaults(TableFunction &table_function) {
	table_function.named_parameters["maximum_object_size"] = LogicalType::UINTEGER;
	table_function.named_parameters["ignore_errors"] = LogicalType::BOOLEAN;
	table_function.named_parameters["format"] = LogicalType::VARCHAR;
	table_function.named_parameters["compression"] = LogicalType::VARCHAR;

	table_function.serialize = Serialize;
	table_function.deserialize = Deserialize;

	table_function.projection_pushdown = true;
	table_function.filter_pushdown = false;
	table_function.filter_prune = false;
}

} // namespace duckdb

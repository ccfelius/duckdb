#pragma once

#include "duckdb/function/compression_function.hpp"
#include "duckdb/storage/table/column_data.hpp"
#include "duckdb/storage/table/scan_state.hpp"
#include "duckdb/storage/table/column_data_checkpointer.hpp"

namespace duckdb {

class EmptyValidityCompression {
public:
	struct EmptyValidityAnalyzeState : public AnalyzeState {
		explicit EmptyValidityAnalyzeState(const CompressionInfo &info) : AnalyzeState(info) {
		}
		idx_t count = 0;
		idx_t non_nulls = 0;
	};
	struct EmptyValidityCompressionState : public CompressionState {
		explicit EmptyValidityCompressionState(ColumnDataCheckpointer &checkpointer, const CompressionInfo &info)
		    : CompressionState(info),
		      function(checkpointer.GetCompressionFunction(CompressionType::COMPRESSION_EMPTY)) {
		}
		optional_ptr<CompressionFunction> function;
	};
	struct EmptyValiditySegmentScanState : public SegmentScanState {
		EmptyValiditySegmentScanState() {
		}
	};

public:
	static CompressionFunction CreateFunction() {
		return CompressionFunction(CompressionType::COMPRESSION_EMPTY, PhysicalType::BIT, InitAnalyze, Analyze,
		                           FinalAnalyze, InitCompression, Compress, FinalizeCompress, InitScan, Scan,
		                           ScanPartial, FetchRow, Skip, InitSegment);
	}

public:
	static unique_ptr<AnalyzeState> InitAnalyze(ColumnData &col_data, PhysicalType type) {
		CompressionInfo info(col_data.GetBlockManager().GetBlockSize());
		return make_uniq<EmptyValidityAnalyzeState>(info);
	}
	static bool Analyze(AnalyzeState &state_p, Vector &input, idx_t count) {
		auto &state = state_p.Cast<EmptyValidityAnalyzeState>();
		UnifiedVectorFormat format;
		input.ToUnifiedFormat(count, format);
		state.non_nulls += format.validity.CountValid(count);
		state.count += count;
		return true;
	}
	static idx_t FinalAnalyze(AnalyzeState &state_p) {
		return 0;
	}
	static unique_ptr<CompressionState> InitCompression(ColumnDataCheckpointer &checkpointer,
	                                                    unique_ptr<AnalyzeState> state_p) {
		auto res = make_uniq<EmptyValidityCompressionState>(checkpointer, state_p->info);
		auto &state = state_p->Cast<EmptyValidityAnalyzeState>();

		auto &db = checkpointer.GetDatabase();
		auto &type = checkpointer.GetType();

		auto row_start = checkpointer.GetRowGroup().start;

		auto &info = state.info;
		auto compressed_segment = ColumnSegment::CreateTransientSegment(db, *res->function, type, row_start,
		                                                                info.GetBlockSize(), info.GetBlockSize());
		compressed_segment->count = state.count;
		if (state.non_nulls != state.count) {
			compressed_segment->stats.statistics.SetHasNullFast();
		}
		if (state.non_nulls == 0) {
			compressed_segment->stats.statistics.SetHasNoNullFast();
		}

		auto &buffer_manager = BufferManager::GetBufferManager(checkpointer.GetDatabase());
		auto handle = buffer_manager.Pin(compressed_segment->block);

		auto &checkpointer_state = checkpointer.GetCheckpointState();
		checkpointer_state.FlushSegment(std::move(compressed_segment), std::move(handle), 0);

		return res;
	}
	static void Compress(CompressionState &state_p, Vector &scan_vector, idx_t count) {
		return;
	}
	static void FinalizeCompress(CompressionState &state_p) {
		return;
	}
	static unique_ptr<SegmentScanState> InitScan(ColumnSegment &segment) {
		return make_uniq<EmptyValiditySegmentScanState>();
	}
	static void ScanPartial(ColumnSegment &segment, ColumnScanState &state, idx_t scan_count, Vector &result,
	                        idx_t result_offset) {
		return;
	}
	static void Scan(ColumnSegment &segment, ColumnScanState &state, idx_t scan_count, Vector &result) {
		return;
	}
	static void FetchRow(ColumnSegment &segment, ColumnFetchState &state, row_t row_id, Vector &result,
	                     idx_t result_idx) {
		return;
	}
	static void Skip(ColumnSegment &segment, ColumnScanState &state, idx_t skip_count) {
		return;
	}
	static unique_ptr<CompressedSegmentState> InitSegment(ColumnSegment &segment, block_id_t block_id,
	                                                      optional_ptr<ColumnSegmentState> segment_state) {
		return nullptr;
	}
};

} // namespace duckdb

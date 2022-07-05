#include "duckdb/common/bitpacking.hpp"
#include "duckdb/storage/checkpoint/write_overflow_strings_to_disk.hpp"
#include "duckdb/storage/string_uncompressed.hpp"
#include "duckdb/function/compression/compression.hpp"
#include "duckdb/storage/table/column_data_checkpointer.hpp"
#include "duckdb/main/config.hpp"
#include "miniz_wrapper.hpp"
#include "fsst.h"
#include <iostream>

namespace duckdb {

typedef struct {
	uint32_t dict_size;
	uint32_t dict_end;
	uint32_t bitpacking_width;
	uint32_t fsst_symbol_table_offset;
} fsst_compression_header_t;

struct FSSTStorage {
	static unique_ptr<AnalyzeState> StringInitAnalyze(ColumnData &col_data, PhysicalType type);
	static bool StringAnalyze(AnalyzeState &state_p, Vector &input, idx_t count);
	static idx_t StringFinalAnalyze(AnalyzeState &state_p);

	static unique_ptr<CompressionState> InitCompression(ColumnDataCheckpointer &checkpointer,
	                                                    unique_ptr<AnalyzeState> analyze_state_p);
	static void Compress(CompressionState &state_p, Vector &scan_vector, idx_t count);
	static void FinalizeCompress(CompressionState &state_p);

	static unique_ptr<SegmentScanState> StringInitScan(ColumnSegment &segment);
	template <bool ALLOW_FSST_VECTORS=false>
	static void StringScanPartial(ColumnSegment &segment, ColumnScanState &state, idx_t scan_count, Vector &result,
	                                    idx_t result_offset);
	static void StringScan(ColumnSegment &segment, ColumnScanState &state, idx_t scan_count, Vector &result);
	static void StringFetchRow(ColumnSegment &segment, ColumnFetchState &state, row_t row_id, Vector &result,
	                                 idx_t result_idx);

	static void SetDictionary(ColumnSegment &segment, BufferHandle &handle, StringDictionaryContainer container);
	static StringDictionaryContainer GetDictionary(ColumnSegment &segment, BufferHandle &handle);
};

//===--------------------------------------------------------------------===//
// Analyze
//===--------------------------------------------------------------------===//
struct FSSTAnalyzeState : public AnalyzeState {
	FSSTAnalyzeState() : count(0), fsst_string_total_size(0), empty_strings(0) {
	}

	~FSSTAnalyzeState() override {
		if (fsst_encoder) {
			fsst_destroy(fsst_encoder);
		}
	}

	fsst_encoder_t *fsst_encoder = nullptr;
	idx_t count;

	std::vector<string> fsst_strings;
	size_t fsst_string_total_size;

	idx_t empty_strings;
};

unique_ptr<AnalyzeState> FSSTStorage::StringInitAnalyze(ColumnData &col_data, PhysicalType type) {
	return make_unique<FSSTAnalyzeState>();
}

bool FSSTStorage::StringAnalyze(AnalyzeState &state_p, Vector &input, idx_t count) {
	auto &state = (FSSTAnalyzeState &)state_p;
	VectorData vdata;
	input.Orrify(count, vdata);

	state.count += count;
	auto data = (string_t *)vdata.data;
	for (idx_t i = 0; i < count; i++) {
		auto idx = vdata.sel->get_index(i);
		if (vdata.validity.RowIsValid(idx)) {
			auto string_size = data[idx].GetSize();

			if (string_size >= StringUncompressed::STRING_BLOCK_LIMIT) {
				return false;
			}

			if (string_size > 0) {
				// TODO this copies the string, can we do better? i.e. we could make the compression api store strings for
				state.fsst_strings.emplace_back(data[idx].GetString());
				state.fsst_string_total_size += string_size;
			} else {
				state.empty_strings++;
			}
		}
	}
	return true;
}

idx_t FSSTStorage::StringFinalAnalyze(AnalyzeState &state_p) {
	auto &state = (FSSTAnalyzeState &)state_p;

	size_t compressed_dict_size = 0;
	size_t max_compressed_string_length = 0;

	auto string_count = state.fsst_strings.size();
	if (string_count) {
		size_t output_buffer_size = state.fsst_string_total_size * 10; // TODO whats the correct size here?

		// TODO improve on this primitive thing.
		std::vector<size_t> fsst_string_sizes;
		std::vector<unsigned char *> fsst_string_ptrs;
		for (auto& str: state.fsst_strings) {
			fsst_string_sizes.push_back(str.size());
			fsst_string_ptrs.push_back((unsigned char*) str.c_str());
		}

		state.fsst_encoder = fsst_create(string_count, &fsst_string_sizes[0], &fsst_string_ptrs[0], 0);

		// TODO: don't encode here!
		auto compressed_ptrs = std::vector<unsigned char *>(string_count, 0);
		auto compressed_sizes = std::vector<size_t>(string_count, 0);
		auto compressed_buffer = std::vector<unsigned char>(output_buffer_size, 0);

		auto res =
		    fsst_compress(state.fsst_encoder, string_count, &fsst_string_sizes[0], &fsst_string_ptrs[0],
		                  output_buffer_size, &compressed_buffer[0], &compressed_sizes[0], &compressed_ptrs[0]);

		if (string_count != res) {
			std::cout << "string count " << string_count << "\n";
			std::cout << "res " << res << "\n";
			throw std::runtime_error("FSST output buffer is too small unexpectedly");
		}
		//	std::cout << "\n";
		//	std::cout << "Dictionary contains " << n << " strings (total " << state.fsst_string_total_size << "
		//bytes)\n"; 	std::cout << "Compressed size is " << (compressed_ptrs[res-1] - compressed_ptrs[0]) +
		//compressed_sizes[res-1] << "\n"; 	std::cout << "Symbol table size is " << serialized_symbol_table_size << "\n";

		// Sum and and Max compressed lengths
		for (auto &size : compressed_sizes) {
			compressed_dict_size += size;
			max_compressed_string_length = MaxValue(max_compressed_string_length, size);
		}
		D_ASSERT(compressed_dict_size == (compressed_ptrs[res - 1] - compressed_ptrs[0]) + compressed_sizes[res - 1]);
	}

	// TODO this returns 0 for all empty strings
	// Note that the minimum width is equal to max string length due to delta encoding
	auto minimum_width = BitpackingPrimitives::MinimumBitWidth(max_compressed_string_length);
	auto bitpacked_offsets_size = BitpackingPrimitives::GetRequiredSize<idx_t>(string_count + state.empty_strings, minimum_width);

	// TODO this forgets both the nulls and the fsst symtable size
	return bitpacked_offsets_size + compressed_dict_size;
}

//===--------------------------------------------------------------------===//
// Compress
//===--------------------------------------------------------------------===//

class FSSTCompressionState : public CompressionState {
public:
	explicit FSSTCompressionState(ColumnDataCheckpointer &checkpointer) : checkpointer(checkpointer) {
		auto &db = checkpointer.GetDatabase();
		auto &config = DBConfig::GetConfig(db);
		function = config.GetCompressionFunction(CompressionType::COMPRESSION_FSST, PhysicalType::VARCHAR);
		CreateEmptySegment(checkpointer.GetRowGroup().start);
	}

	~FSSTCompressionState() override {
		if (fsst_encoder) {
			fsst_destroy(fsst_encoder);
		}
	}

	void CreateEmptySegment(idx_t row_start) {
		auto &db = checkpointer.GetDatabase();
		auto &type = checkpointer.GetType();
		auto compressed_segment = ColumnSegment::CreateTransientSegment(db, type, row_start);
		current_segment = move(compressed_segment);

		current_segment->function = function;

		// Reset the buffers and string map
		index_buffer.clear();

		// TODO start at 0 or 1?
		current_width = 0;

		// Reset the pointers into the current segment
		auto &buffer_manager = BufferManager::GetBufferManager(current_segment->db);
		current_handle = buffer_manager.Pin(current_segment->block);
		current_dictionary = DictionaryCompressionStorage::GetDictionary(*current_segment, *current_handle);
		current_end_ptr = current_handle->node->buffer + current_dictionary.end;
	}

	void UpdateState(string_t uncompressed_string, unsigned char *compressed_string, size_t compressed_string_len) {

		if (!HasEnoughSpace(compressed_string_len)) {
			Flush();
			D_ASSERT(HasEnoughSpace(compressed_string_len));
		}

		UncompressedStringStorage::UpdateStringStats(current_segment->stats, uncompressed_string);

		// Write string into dictionary
		current_dictionary.size += compressed_string_len;
		auto dict_pos = current_end_ptr - current_dictionary.size;
		memcpy(dict_pos, compressed_string, compressed_string_len);
		current_dictionary.Verify();

		// add dict index TODO delta encode immediately by just doing string length here straigh away?
		index_buffer.push_back(current_dictionary.size);

		max_compressed_string_length = MaxValue(max_compressed_string_length, compressed_string_len);

		current_width = BitpackingPrimitives::MinimumBitWidth(max_compressed_string_length);
		current_segment->count++;
	}

	// Nulls and empty values are both treated the same:
	void AddNullOrEmpty() {
		index_buffer.push_back(!index_buffer.empty() ? index_buffer.back() : 0);
		current_segment->count++;
	}

	bool HasEnoughSpace(size_t string_len) {
		bitpacking_width_t required_minimum_width;
		if (string_len > max_compressed_string_length) {
			required_minimum_width = BitpackingPrimitives::MinimumBitWidth(string_len);
		} else {
			required_minimum_width = current_width;
		}

		size_t current_dict_size = current_dictionary.size;
		idx_t current_string_count = index_buffer.size();

		// TODO we don't need to calculate this every time?
		size_t dict_offsets_size =
		    BitpackingPrimitives::GetRequiredSize<idx_t>(current_string_count + 1, required_minimum_width);

		// TODO switch to a symbol table per RowGroup
		idx_t required_space = sizeof(fsst_compression_header_t) + current_dict_size + dict_offsets_size + string_len +
		                       fsst_serialized_symbol_table_size;

		return required_space <= Storage::BLOCK_SIZE;
	}

	void Flush(bool final = false) {
		auto next_start = current_segment->start + current_segment->count;

		auto segment_size = Finalize();
		auto &state = checkpointer.GetCheckpointState();
		state.FlushSegment(move(current_segment), segment_size);

		if (!final) {
			CreateEmptySegment(next_start);
		}
	}

	idx_t Finalize() {
		auto &buffer_manager = BufferManager::GetBufferManager(current_segment->db);
		auto handle = buffer_manager.Pin(current_segment->block);
		D_ASSERT(current_dictionary.end == Storage::BLOCK_SIZE);

		// calculate sizes
		auto compressed_index_buffer_size =
		    BitpackingPrimitives::GetRequiredSize<sel_t>(current_segment->count, current_width);
		auto total_size = sizeof(fsst_compression_header_t) + compressed_index_buffer_size + current_dictionary.size +
		                  fsst_serialized_symbol_table_size;

		// calculate ptr and offsets
		auto base_ptr = handle->node->buffer;
		auto header_ptr = (fsst_compression_header_t *)base_ptr;
		auto compressed_index_buffer_offset = sizeof(fsst_compression_header_t);
		auto symbol_table_offset = compressed_index_buffer_offset + compressed_index_buffer_size;

		// Delta encode + bitpack index_buffer
		uint32_t prev = index_buffer[0];
		for (idx_t i = 1; i < index_buffer.size(); i++) {
			uint32_t current_delta = index_buffer[i] - prev;
			prev = index_buffer[i];
			index_buffer[i] = current_delta;
		}

		D_ASSERT(current_segment->count == index_buffer.size());
		BitpackingPrimitives::PackBuffer<sel_t, false>(base_ptr + compressed_index_buffer_offset,
		                                               (uint32_t *)(index_buffer.data()), current_segment->count,
		                                               current_width);

		// Write the fsst symbol table or nothing TODO has this been serialized already?
		if (fsst_encoder != nullptr) {
			memcpy(base_ptr + symbol_table_offset, &fsst_serialized_symbol_table[0], fsst_serialized_symbol_table_size);
		} else {
			memset(base_ptr + symbol_table_offset, 0, fsst_serialized_symbol_table_size);
		}

		Store<uint32_t>(symbol_table_offset, (data_ptr_t)&header_ptr->fsst_symbol_table_offset);
		Store<uint32_t>((uint32_t)current_width, (data_ptr_t)&header_ptr->bitpacking_width);

		// TODO: MOVING!  also think about code deduplication!
		if (true || total_size >= DictionaryCompressionStorage::COMPACTION_FLUSH_LIMIT) {
			// the block is full enough, don't bother moving around the dictionary
			return Storage::BLOCK_SIZE;
		}
		// the block has space left: figure out how much space we can save
		auto move_amount = Storage::BLOCK_SIZE - total_size;
		// move the dictionary so it lines up exactly with the offsets
		auto new_dictionary_offset = symbol_table_offset + fsst_serialized_symbol_table_size;
		memmove(base_ptr + new_dictionary_offset, base_ptr + current_dictionary.end - current_dictionary.size,
		        current_dictionary.size);
		current_dictionary.end -= move_amount;
		D_ASSERT(current_dictionary.end == total_size);
		// write the new dictionary (with the updated "end")
		DictionaryCompressionStorage::SetDictionary(*current_segment, *handle, current_dictionary);

		return total_size;
	}

	ColumnDataCheckpointer &checkpointer;
	CompressionFunction *function;

	// State regarding current segment
	unique_ptr<ColumnSegment> current_segment;
	unique_ptr<BufferHandle> current_handle;
	StringDictionaryContainer current_dictionary;
	data_ptr_t current_end_ptr;

	// Buffers and map for current segment
	std::vector<uint32_t> index_buffer;

	size_t max_compressed_string_length = 0;
	bitpacking_width_t current_width = 0;

	fsst_encoder_t *fsst_encoder = nullptr;
	unsigned char fsst_serialized_symbol_table[sizeof(fsst_decoder_t)];
	size_t fsst_serialized_symbol_table_size = sizeof(fsst_decoder_t); // TODO calculate actual value somewhere?
};

unique_ptr<CompressionState> FSSTStorage::InitCompression(ColumnDataCheckpointer &checkpointer,
                                                          unique_ptr<AnalyzeState> analyze_state_p) {
	auto analyze_state = dynamic_cast<FSSTAnalyzeState *>(analyze_state_p.get());
	auto compression_state = make_unique<FSSTCompressionState>(checkpointer);

	if (analyze_state->fsst_encoder != nullptr) {
		compression_state->fsst_encoder = analyze_state->fsst_encoder;
		compression_state->fsst_serialized_symbol_table_size =
		    fsst_export(compression_state->fsst_encoder, &compression_state->fsst_serialized_symbol_table[0]);
		analyze_state->fsst_encoder = nullptr;
	}

	return compression_state;
}

void FSSTStorage::Compress(CompressionState &state_p, Vector &scan_vector, idx_t count) {
	auto &state = (FSSTCompressionState &)state_p;

	// Get vector data
	VectorData vdata;
	scan_vector.Orrify(count, vdata);
	auto data = (string_t *)vdata.data;

	// Collect pointers to strings to compress
	vector<size_t> sizes_in;
	vector<unsigned char *> strings_in;
	size_t total_size = 0;
	idx_t total_count = 0;
	for (idx_t i = 0; i < count; i++) {
		auto idx = vdata.sel->get_index(i);

		// Note: we treat nulls and empty strings the same, due to
		auto row_is_valid = vdata.validity.RowIsValid(idx) && data[idx].GetSize();
		if (row_is_valid) {
			total_count++;
			total_size += data[idx].GetSize();
			sizes_in.push_back(data[idx].GetSize());
			strings_in.push_back((unsigned char *)data[idx].GetDataUnsafe());
		}
	}

	// Only Nulls, nothing to compress
	if (total_count == 0 || state.fsst_encoder == nullptr) {
		for (idx_t i = 0; i < count; i++) {
			state.AddNullOrEmpty();
		}
		return;
	}

	// Compress buffers
	size_t compress_buffer_size = MaxValue<size_t>(total_size * 3 + 7, 1); // TODO what size?
	vector<unsigned char *> strings_out(total_count, nullptr);
	vector<size_t> sizes_out(total_count, 0);
	vector<unsigned char> compress_buffer(compress_buffer_size, 0);

	auto res = fsst_compress(
	    state.fsst_encoder,   		/* IN: encoder obtained from fsst_create(). */
	    total_count,          		/* IN: number of strings in batch to compress. */
	    &sizes_in[0],         /* IN: byte-lengths of the inputs */
	    &strings_in[0],       /* IN: input string start pointers. */
	    compress_buffer_size, 		/* IN: byte-length of output buffer. */
	    &compress_buffer[0], /* OUT: memorxy buffer to put the compressed strings in (one after the other). */
	    &sizes_out[0],       /* OUT: byte-lengths of the compressed strings. */
	    &strings_out[0]      /* OUT: output string start pointers. Will all point into [output,output+size). */
	);

	if (res != total_count) {
		// TODO throwing here will cause some crash?
		throw std::runtime_error("FSST: Not all strings were compressed!");
	}

	// Push the compressed strings to the compression state one by one
	idx_t compressed_idx = 0;
	for (idx_t i = 0; i < count; i++) {
		auto idx = vdata.sel->get_index(i);
		auto row_is_valid = vdata.validity.RowIsValid(idx) && data[idx].GetSize();
		if (row_is_valid) {
			state.UpdateState(data[idx], strings_out[compressed_idx], sizes_out[compressed_idx]);
			compressed_idx++;
		} else {
			state.AddNullOrEmpty();
		}
	}
}

void FSSTStorage::FinalizeCompress(CompressionState &state_p) {
	auto &state = (FSSTCompressionState &)state_p;
	state.Flush(true);
}

//===--------------------------------------------------------------------===//
// Scan
//===--------------------------------------------------------------------===//
struct FSSTScanState : public StringScanState {
	FSSTScanState() {
		ResetStoredDelta();
	}

	buffer_ptr<void> fsst_decoder;
	bitpacking_width_t current_width;

	// To speed up delta decoding we store the last index
	uint32_t last_known_index;
	int64_t last_known_row;

	void StoreLastDelta(uint32_t value, int64_t row) {
		last_known_index = value;
		last_known_row = row;
	}
	void ResetStoredDelta() {
		last_known_index = 0;
		last_known_row = -1;
	}
};

// Returns false if no symbol table was found. This means all strings are either empty or null
bool ParseFSSTSegmentHeader(data_ptr_t base_ptr, fsst_decoder_t *decoder_out, bitpacking_width_t* width_out) {
	auto header_ptr = (fsst_compression_header_t *)base_ptr;
	auto fsst_symbol_table_offset = Load<uint32_t>((data_ptr_t)&header_ptr->fsst_symbol_table_offset);
	*width_out = (bitpacking_width_t)(Load<uint32_t>((data_ptr_t)&header_ptr->bitpacking_width));
	return fsst_import(decoder_out, base_ptr + fsst_symbol_table_offset);;
}

unique_ptr<SegmentScanState> FSSTStorage::StringInitScan(ColumnSegment &segment) {
	auto state = make_unique<FSSTScanState>();
	auto &buffer_manager = BufferManager::GetBufferManager(segment.db);
	state->handle = buffer_manager.Pin(segment.block);
	auto base_ptr = state->handle->node->buffer + segment.GetBlockOffset();

	state->fsst_decoder = make_buffer<fsst_decoder_t>();
	auto retval = ParseFSSTSegmentHeader(base_ptr, (fsst_decoder_t*)state->fsst_decoder.get(), &state->current_width);
	if (!retval) {
		state->fsst_decoder = nullptr;
	}

	return move(state);
}

void DeltaDecodeIndices(uint32_t*buffer_in, uint32_t*buffer_out, idx_t decode_count, uint32_t last_known_value) {
	buffer_out[0] = buffer_in[0];
	buffer_out[0] += last_known_value;
	for (idx_t i = 1; i < decode_count; i++) {
		buffer_out[i] = buffer_in[i] + buffer_out[i-1];
	}
}

void BitUnpackRange(data_ptr_t src_ptr, data_ptr_t dst_ptr, idx_t count, idx_t row, bitpacking_width_t width) {
	auto bitunpack_src_ptr = &src_ptr[(row * width) / 8];
	BitpackingPrimitives::UnPackBuffer<uint32_t>(dst_ptr, bitunpack_src_ptr, count, width);
}

typedef struct BPDeltaDecodeOffsets {
	idx_t delta_decode_start_row;
	idx_t bitunpack_alignment_offset;
	idx_t bitunpack_start_row;
	idx_t unused_delta_decoded_values;
	idx_t scan_offset;
	idx_t total_delta_decode_count;
	idx_t total_bitunpack_count;
} bp_delta_offsets_t;

// The calculation of offsets and counts is a bit tricky, due to:
// - bitunpacking needs to be aligned to BITPACKING_ALGORITHM_GROUP_SIZE
// - delta decoding may use the stored last known value.
//
// To help visualize:
//   | 											ColumnSegment buffer											   |
//   |  untouched  |  bp alignment  |  unused delta values  |  values to scan  |  bitpack alignment  |  untouched  |
// 1:							    X
// 2:			   < -------------- >
// 3:			   X
// 4:              					< --------------------- >
// 5:			   < -------------------------------------- >
// 6:			   					< ---------------------------------------- >
// 7:			   < ------------------------------------------------------------------------------- >
bp_delta_offsets_t CalculateBpDeltaOffsets(idx_t last_known_row, idx_t start, idx_t scan_count) {
	D_ASSERT((idx_t)(last_known_row + 1) <= start);
	bp_delta_offsets_t result;

	result.delta_decode_start_row = (last_known_row+1); // 1
	result.bitunpack_alignment_offset = result.delta_decode_start_row % BitpackingPrimitives::BITPACKING_ALGORITHM_GROUP_SIZE; // 2
	result.bitunpack_start_row = result.delta_decode_start_row - result.bitunpack_alignment_offset; // 3
	result.unused_delta_decoded_values = start - result.delta_decode_start_row; // 4
	result.scan_offset = result.bitunpack_alignment_offset + result.unused_delta_decoded_values; // 5
	result.total_delta_decode_count = scan_count + result.unused_delta_decoded_values; // 6
	result.total_bitunpack_count = BitpackingPrimitives::RoundUpToAlgorithmGroupSize<idx_t>(scan_count + result.scan_offset); // 7

	D_ASSERT(result.total_delta_decode_count + result.bitunpack_alignment_offset <= result.total_bitunpack_count);
	return result;
}


//===--------------------------------------------------------------------===//
// Scan base data
//===--------------------------------------------------------------------===//
template <bool ALLOW_FSST_VECTORS>
void FSSTStorage::StringScanPartial(ColumnSegment &segment, ColumnScanState &state, idx_t scan_count, Vector &result,

                                    idx_t result_offset) {

	auto &scan_state = (FSSTScanState &)*state.scan_state;
	auto start = segment.GetRelativeIndex(state.row_index);

	auto baseptr = scan_state.handle->node->buffer + segment.GetBlockOffset();
	auto dict = GetDictionary(segment, *scan_state.handle);
	auto base_data = (data_ptr_t)(baseptr + sizeof(fsst_compression_header_t));
	string_t* result_data;
	unique_ptr<Vector> output_vector;

	if (ALLOW_FSST_VECTORS) {
		D_ASSERT(result_offset == 0);
		if (scan_state.fsst_decoder) {
			D_ASSERT(result_offset == 0 || result.GetVectorType() == VectorType::FSST_VECTOR);
			result.SetVectorType(VectorType::FSST_VECTOR);
			FSSTVector::RegisterDecoder(result, scan_state.fsst_decoder);
			result_data = FSSTVector::GetCompressedData<string_t>(result);
		} else {
			D_ASSERT(result.GetVectorType() == VectorType::FLAT_VECTOR);
			result_data = FlatVector::GetData<string_t>(result);
		}
	} else {
		D_ASSERT(result.GetVectorType() == VectorType::FLAT_VECTOR);
		output_vector = make_unique<Vector>(result.GetType(), scan_count);
		output_vector->SetVectorType(VectorType::FSST_VECTOR);
		FSSTVector::RegisterDecoder(*output_vector, scan_state.fsst_decoder);
		result_data = FSSTVector::GetCompressedData<string_t>(*output_vector);
	}

	// TODO what if the segment changes? It may go wrong?
	if (start == 0 || scan_state.last_known_row >= (int64_t)start) {
		scan_state.ResetStoredDelta();
	}

	auto offsets = CalculateBpDeltaOffsets(scan_state.last_known_row, start, scan_count);

	auto bitunpack_buffer = unique_ptr<uint32_t[]>(new uint32_t[offsets.total_bitunpack_count]);
	BitUnpackRange(base_data, (data_ptr_t)bitunpack_buffer.get(), offsets.total_bitunpack_count, offsets.bitunpack_start_row, scan_state.current_width);
	auto delta_decode_buffer = unique_ptr<uint32_t[]>(new uint32_t[offsets.total_delta_decode_count]);
	DeltaDecodeIndices(bitunpack_buffer.get() + offsets.bitunpack_alignment_offset, delta_decode_buffer.get(), offsets.total_delta_decode_count, scan_state.last_known_index);

	// Lookup decompressed offsets in dict
	for (idx_t i = 0; i < scan_count; i++) {
		uint32_t string_length = bitunpack_buffer[i + offsets.scan_offset];
		result_data[i] =
		    UncompressedStringStorage::FetchStringFromDict(segment, dict, result, baseptr, delta_decode_buffer[i + offsets.unused_delta_decoded_values], string_length);
	}

	scan_state.StoreLastDelta(delta_decode_buffer[scan_count + offsets.unused_delta_decoded_values - 1],
	                          start + scan_count - 1);

	if (!ALLOW_FSST_VECTORS) {
		VectorOperations::Copy(*output_vector, result, scan_count, 0, result_offset);
		D_ASSERT(result.GetVectorType() == VectorType::FLAT_VECTOR);
	}
}

void FSSTStorage::StringScan(ColumnSegment &segment, ColumnScanState &state, idx_t scan_count, Vector &result) {
	StringScanPartial<true>(segment, state, scan_count, result, 0);
}

//===--------------------------------------------------------------------===//
// Fetch
//===--------------------------------------------------------------------===//
void FSSTStorage::StringFetchRow(ColumnSegment &segment, ColumnFetchState &state, row_t row_id, Vector &result,
                                 idx_t result_idx) {

	auto &buffer_manager = BufferManager::GetBufferManager(segment.db);
	auto handle = buffer_manager.Pin(segment.block);
	auto base_ptr = handle->node->buffer + segment.GetBlockOffset();
	auto base_data = (data_ptr_t)(base_ptr + sizeof(fsst_compression_header_t));
	auto dict = GetDictionary(segment, *handle);

	fsst_decoder_t decoder;
	bitpacking_width_t width;
	auto have_symbol_table = ParseFSSTSegmentHeader(base_ptr, &decoder, &width);

	auto result_data = FlatVector::GetData<string_t>(result);
	unsigned char decompress_buffer[StringUncompressed::STRING_BLOCK_LIMIT+1];

	if (have_symbol_table) {
		// We basically just do a scan of 1 which is kinda expensive as we need to repeatedly delta decode until we
		// reach the row we want, we could consider a more clever caching trick if this is slow
		auto offsets = CalculateBpDeltaOffsets(-1, row_id, 1);

		auto bitunpack_buffer = unique_ptr<uint32_t[]>(new uint32_t[offsets.total_bitunpack_count]);
		BitUnpackRange(base_data, (data_ptr_t)bitunpack_buffer.get(), offsets.total_bitunpack_count, offsets.bitunpack_start_row, width);
		auto delta_decode_buffer = unique_ptr<uint32_t[]>(new uint32_t[offsets.total_delta_decode_count]);
		DeltaDecodeIndices(bitunpack_buffer.get() + offsets.bitunpack_alignment_offset, delta_decode_buffer.get(), offsets.total_delta_decode_count, 0);

		uint32_t string_length = bitunpack_buffer[offsets.scan_offset];

		string_t compressed_string = UncompressedStringStorage::FetchStringFromDict(segment, dict, result, base_ptr, delta_decode_buffer[offsets.unused_delta_decoded_values], string_length);

		auto decompressed_string_size = fsst_decompress(
		    &decoder,
		    compressed_string.GetSize(),
		    (unsigned char*)compressed_string.GetDataUnsafe(),
		    StringUncompressed::STRING_BLOCK_LIMIT+1,
		    &decompress_buffer[0]
		);

		D_ASSERT(decompressed_string_size <= StringUncompressed::STRING_BLOCK_LIMIT);

		auto decompressed_string = StringVector::AddString(result, (char*)decompress_buffer, decompressed_string_size);
		result_data[result_idx] = decompressed_string;
	} else {
		// There's no fsst symtable, this only happens for empty strings or nulls, we can just emit an empty string
		result_data[result_idx] = string_t(nullptr, 0);
	}
}

//===--------------------------------------------------------------------===//
// Get Function
//===--------------------------------------------------------------------===//
CompressionFunction FSSTFun::GetFunction(PhysicalType data_type) {
	D_ASSERT(data_type == PhysicalType::VARCHAR);
	return CompressionFunction(
	    CompressionType::COMPRESSION_FSST, data_type, FSSTStorage::StringInitAnalyze, FSSTStorage::StringAnalyze,
	    FSSTStorage::StringFinalAnalyze, FSSTStorage::InitCompression, FSSTStorage::Compress,
	    FSSTStorage::FinalizeCompress, FSSTStorage::StringInitScan, FSSTStorage::StringScan,
	    FSSTStorage::StringScanPartial<false>, FSSTStorage::StringFetchRow, UncompressedFunctions::EmptySkip);
}

bool FSSTFun::TypeIsSupported(PhysicalType type) {
	return type == PhysicalType::VARCHAR;
}

//===--------------------------------------------------------------------===//
// Helper Functions
//===--------------------------------------------------------------------===//
void FSSTStorage::SetDictionary(ColumnSegment &segment, BufferHandle &handle, StringDictionaryContainer container) {
	auto header_ptr = (fsst_compression_header_t *)(handle.node->buffer + segment.GetBlockOffset());
	Store<uint32_t>(container.size, (data_ptr_t)&header_ptr->dict_size);
	Store<uint32_t>(container.end, (data_ptr_t)&header_ptr->dict_end);
}

StringDictionaryContainer FSSTStorage::GetDictionary(ColumnSegment &segment, BufferHandle &handle) {
	auto header_ptr = (fsst_compression_header_t *)(handle.node->buffer + segment.GetBlockOffset());
	StringDictionaryContainer container;
	container.size = Load<uint32_t>((data_ptr_t)&header_ptr->dict_size);
	container.end = Load<uint32_t>((data_ptr_t)&header_ptr->dict_end);
	return container;
}
} // namespace duckdb

//===----------------------------------------------------------------------===//
//                         DuckDB
//
// duckdb/storage/compression/alp/alp_compress.hpp
//
//
//===----------------------------------------------------------------------===//

#pragma once

#define ENCRYPT 1
#define TEST_KEY "0123456789112345"

#include "duckdb/common/helper.hpp"
#include "duckdb/common/limits.hpp"
#include "duckdb/common/operator/subtract.hpp"
#include "duckdb/common/types/null_value.hpp"
#include "duckdb/function/compression/compression.hpp"
#include "duckdb/function/compression_function.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/storage/buffer_manager.hpp"
#include "duckdb/storage/compression/alp/algorithm/alp.hpp"
#include "duckdb/storage/compression/alp/alp_analyze.hpp"
#include "duckdb/storage/compression/patas/patas.hpp"
#include "duckdb/storage/table/column_data_checkpointer.hpp"
#include "duckdb/storage/table/column_segment.hpp"
#include "duckdb/common/encryption_state.hpp"
#include "mbedtls_wrapper.hpp"

#include <functional>

namespace duckdb {

template <class T>
struct AlpCompressionState : public CompressionState {

public:
	using EXACT_TYPE = typename FloatingToExact<T>::TYPE;

	AlpCompressionState(ColumnDataCheckpointer &checkpointer, AlpAnalyzeState<T> *analyze_state)
	    : CompressionState(analyze_state->info), checkpointer(checkpointer),
	      function(checkpointer.GetCompressionFunction(CompressionType::COMPRESSION_ALP)) {
		CreateEmptySegment(checkpointer.GetRowGroup().start);

		//! Combinations found on the analyze step are needed for compression
		state.best_k_combinations = analyze_state->state.best_k_combinations;
	}

	ColumnDataCheckpointer &checkpointer;
	CompressionFunction &function;
	unique_ptr<ColumnSegment> current_segment;
	BufferHandle handle;

	idx_t vector_idx = 0;
	idx_t nulls_idx = 0;
	idx_t vectors_flushed = 0;
	idx_t data_bytes_used = 0;

	data_ptr_t data_ptr;     // Pointer to next free spot in segment;
	data_ptr_t metadata_ptr; // Reverse pointer to the next free spot for the metadata; used in decoding to SKIP vectors
	uint32_t next_vector_byte_index_start = AlpConstants::HEADER_SIZE;

	T input_vector[AlpConstants::ALP_VECTOR_SIZE];
	uint16_t vector_null_positions[AlpConstants::ALP_VECTOR_SIZE];

	// predefine nonce and key
	unsigned char iv[16];
	const string key = TEST_KEY;

	alp::AlpCompressionState<T, false> state;

public:
	void SetIV(){
		memcpy((void*)iv, "12345678901", 12);
		memset((void *)iv, 0, sizeof(iv) - 4);
		iv[12] = 0x00;
		iv[13] = 0x00;
		iv[14] = 0x00;
		iv[15] = 0x00;
	};

	void InitializeEncryption(){
		state.encryption_state = state.ssl_factory.CreateEncryptionState();
		SetIV();
		state.encryption_state->InitializeEncryption(iv, 16, &key);
	}

	size_t EncryptSegment(const_data_ptr_t in, idx_t in_len, data_ptr_t out, idx_t out_len) {
		return state.encryption_state->Process(in, in_len, out, out_len);
	}

	// Returns the space currently used in the segment (in bytes)
	idx_t UsedSpace() const {
		return AlpConstants::METADATA_POINTER_SIZE + data_bytes_used;
	}

	// Returns the required space to store the newly compressed vector
	idx_t RequiredSpace() {
		idx_t required_space =
		    state.bp_size + (state.exceptions_count * (sizeof(EXACT_TYPE) + AlpConstants::EXCEPTION_POSITION_SIZE)) +
		    AlpConstants::EXPONENT_SIZE + AlpConstants::FACTOR_SIZE + AlpConstants::EXCEPTIONS_COUNT_SIZE +
		    AlpConstants::FOR_SIZE + AlpConstants::BIT_WIDTH_SIZE;
		return required_space;
	}

	bool HasEnoughSpace() {
		//! If [start of block + used space + required space] is more than whats left (current position
		//! of metadata pointer - the size of a new metadata pointer)
		if ((handle.Ptr() + AlignValue(UsedSpace() + RequiredSpace())) >=
		    (metadata_ptr - AlpConstants::METADATA_POINTER_SIZE)) {
			return false;
		}
		return true;
	}

	void ResetVector() {
		state.Reset();
	}

	void CreateEmptySegment(idx_t row_start) {
		auto &db = checkpointer.GetDatabase();
		auto &type = checkpointer.GetType();

		auto compressed_segment = ColumnSegment::CreateTransientSegment(db, type, row_start);
		current_segment = std::move(compressed_segment);
		current_segment->function = function;

		auto &buffer_manager = BufferManager::GetBufferManager(current_segment->db);
		handle = buffer_manager.Pin(current_segment->block);

		// The pointer to the start of the compressed data.
		data_ptr = handle.Ptr() + current_segment->GetBlockOffset() + AlpConstants::HEADER_SIZE;
		// The pointer to the start of the metadata.
		metadata_ptr = handle.Ptr() + current_segment->GetBlockOffset() + info.GetBlockSize();
		next_vector_byte_index_start = AlpConstants::HEADER_SIZE;
	}

	void CompressVector() {
		if (nulls_idx) {
			alp::AlpUtils::FindAndReplaceNullsInVector<T>(input_vector, vector_null_positions, vector_idx, nulls_idx);
		}
		alp::AlpCompression<T, false>::Compress(input_vector, vector_idx, vector_null_positions, nulls_idx, state);
		//! Check if the compressed vector fits on current segment
		if (!HasEnoughSpace()) {
			auto row_start = current_segment->start + current_segment->count;
			FlushSegment();
			CreateEmptySegment(row_start);
		}

		if (vector_idx != nulls_idx) { //! At least there is one valid value in the vector
			for (idx_t i = 0; i < vector_idx; i++) {
				NumericStats::Update<T>(current_segment->stats.statistics, input_vector[i]);
			}
		}
		current_segment->count += vector_idx;
		FlushVector();
	}

	size_t EncryptVector(const_data_ptr_t in, idx_t in_len, data_ptr_t out, idx_t out_len) {
		return state.encryption_state->Process(in, in_len, out, out_len);
	}

	void SerializeMetadata(data_ptr_t data_ptr) {
		Store<uint8_t>(state.vector_encoding_indices.exponent, data_ptr);
		data_ptr += AlpConstants::EXPONENT_SIZE;

		Store<uint8_t>(state.vector_encoding_indices.factor, data_ptr);
		data_ptr += AlpConstants::FACTOR_SIZE;

		Store<uint16_t>(state.exceptions_count, data_ptr);
		data_ptr += AlpConstants::EXCEPTIONS_COUNT_SIZE;

		Store<uint64_t>(state.frame_of_reference, data_ptr);
		data_ptr += AlpConstants::FOR_SIZE;

		Store<uint8_t>(UnsafeNumericCast<uint8_t>(state.bit_width), data_ptr);
		data_ptr += AlpConstants::BIT_WIDTH_SIZE;
	}

	// Stores the vector and its metadata
	void FlushVector() {

		idx_t bytes_used = RequiredSpace();

		// first we encrypt 13 bytes of AlpConstants
		idx_t metadata_bytes = AlpConstants::EXPONENT_SIZE + AlpConstants::FACTOR_SIZE + AlpConstants::EXCEPTIONS_COUNT_SIZE
		                       + AlpConstants::FOR_SIZE + AlpConstants::BIT_WIDTH_SIZE;

		// create a buffer for encryption
		// TODO: this buffer is unnecessary, we can copy directly to the data_ptr
		uint8_t *buffer = new uint8_t[bytes_used];
		SerializeMetadata(buffer);
		buffer += metadata_bytes;

		// copy encoded values to buffer to encrypt
		memcpy(buffer, state.values_encoded, state.bp_size);
		buffer += state.bp_size;

		// We should never go out of bounds in the values_encoded array
		D_ASSERT((AlpConstants::ALP_VECTOR_SIZE * 8) >= state.bp_size);

		if (state.exceptions_count > 0) {
			memcpy(buffer, state.exceptions, sizeof(EXACT_TYPE) * state.exceptions_count);
			buffer += sizeof(EXACT_TYPE) * state.exceptions_count;
			memcpy(buffer, state.exceptions_positions,
			       AlpConstants::EXCEPTION_POSITION_SIZE * state.exceptions_count);
			buffer += AlpConstants::EXCEPTION_POSITION_SIZE * state.exceptions_count;
		}

		data_bytes_used += bytes_used;

		// auto size_vector = EncryptVector(buffer - bytes_used, bytes_used, data_ptr, bytes_used);
		//D_ASSERT(size_vector == bytes_used);

		data_ptr += bytes_used;

		// Write pointer to the vector data (metadata)
		metadata_ptr -= sizeof(uint32_t);
		Store<uint32_t>(next_vector_byte_index_start, metadata_ptr);
		next_vector_byte_index_start = NumericCast<uint32_t>(UsedSpace());

		vectors_flushed++;
		vector_idx = 0;
		nulls_idx = 0;
		ResetVector();
	}

	void FlushSegment() {
		auto &checkpoint_state = checkpointer.GetCheckpointState();
		auto dataptr = handle.Ptr();

		InitializeEncryption();

		idx_t metadata_offset = AlignValue(UsedSpace());

		// Verify that the metadata_ptr is not smaller than the space used by the data
		D_ASSERT(dataptr + metadata_offset <= metadata_ptr);

		auto bytes_used_by_metadata = UnsafeNumericCast<idx_t>(dataptr + info.GetBlockSize() - metadata_ptr);

		// Initially the total segment size is the size of the block
		auto total_segment_size = info.GetBlockSize();

		//! We compact the block if the space used is less than a threshold
		const auto used_space_percentage =
		    static_cast<float>(metadata_offset + bytes_used_by_metadata) / static_cast<float>(total_segment_size);
		if (used_space_percentage < AlpConstants::COMPACT_BLOCK_THRESHOLD) {
#ifdef DEBUG
			//! Copy the first 4 bytes of the metadata
			uint32_t verify_bytes;
			memcpy((void *)&verify_bytes, metadata_ptr, 4);
#endif
			memmove(dataptr + metadata_offset, metadata_ptr, bytes_used_by_metadata);
#ifdef DEBUG
			//! Now assert that the memmove was correct
			D_ASSERT(verify_bytes == *(uint32_t *)(dataptr + metadata_offset));
#endif
			total_segment_size = metadata_offset + bytes_used_by_metadata;
		}

		// Store the offset to the end of metadata (to be used as a backwards pointer in decoding)
		Store<uint32_t>(NumericCast<uint32_t>(total_segment_size), dataptr);
		dataptr += sizeof(uint32_t );

		// Encrypt the segment (block)
		const auto ciphertext_size = metadata_offset - sizeof(uint32_t);
		// create a buffer to encrypt the segment
		uint8_t *buffer = new uint8_t[ciphertext_size];
		auto size_vector = EncryptSegment(dataptr, ciphertext_size, buffer, ciphertext_size);
		// auto size_vector = EncryptSegment(dataptr + sizeof(uint32_t), ciphertext_size, dataptr + sizeof(uint32_t), ciphertext_size);
		D_ASSERT(size_vector == ciphertext_size);

		//! Copy the first 4 bytes of the metadata
//		uint32_t verify_encrypted_bytes;
//		memcpy((void *)&verify_encrypted_bytes, buffer, 4);
		memmove(dataptr, buffer, ciphertext_size);

		//! Now assert that the memmove of encrypted bytes was correct
//		D_ASSERT(verify_encrypted_bytes == *(uint32_t *)(dataptr + sizeof(uint32_t)));

		dataptr -= sizeof(uint32_t);

		handle.Destroy();
		checkpoint_state.FlushSegment(std::move(current_segment), total_segment_size);
		data_bytes_used = 0;
		vectors_flushed = 0;
	}

	void Finalize() {
		if (vector_idx != 0) {
			CompressVector();
			D_ASSERT(vector_idx == 0);
		}

		FlushSegment();
		current_segment.reset();
	}

	void Append(UnifiedVectorFormat &vdata, idx_t count) {
		auto data = UnifiedVectorFormat::GetData<T>(vdata);
		idx_t values_left_in_data = count;
		idx_t offset_in_data = 0;
		while (values_left_in_data > 0) {
			// We calculate until which value in data we must go to fill the input_vector
			// to avoid checking if input_vector is filled in each iteration
			auto values_to_fill_alp_input =
			    MinValue<idx_t>(AlpConstants::ALP_VECTOR_SIZE - vector_idx, values_left_in_data);
			if (vdata.validity.AllValid()) { //! We optimize a loop when there are no null
				for (idx_t i = 0; i < values_to_fill_alp_input; i++) {
					auto idx = vdata.sel->get_index(offset_in_data + i);
					T value = data[idx];
					input_vector[vector_idx + i] = value;
				}
			} else {
				for (idx_t i = 0; i < values_to_fill_alp_input; i++) {
					auto idx = vdata.sel->get_index(offset_in_data + i);
					T value = data[idx];
					bool is_null = !vdata.validity.RowIsValid(idx);
					//! We resolve null values with a predicated comparison
					vector_null_positions[nulls_idx] = UnsafeNumericCast<uint16_t>(vector_idx + i);
					nulls_idx += is_null;
					input_vector[vector_idx + i] = value;
				}
			}
			offset_in_data += values_to_fill_alp_input;
			values_left_in_data -= values_to_fill_alp_input;
			vector_idx += values_to_fill_alp_input;
			// We still need this check since we could have an incomplete input_vector at the end of data
			if (vector_idx == AlpConstants::ALP_VECTOR_SIZE) {
				CompressVector();
				D_ASSERT(vector_idx == 0);
			}
		}
	}
};

template <class T>
unique_ptr<CompressionState> AlpInitCompression(ColumnDataCheckpointer &checkpointer, unique_ptr<AnalyzeState> state) {
	return make_uniq<AlpCompressionState<T>>(checkpointer, (AlpAnalyzeState<T> *)state.get());
}

template <class T>
void AlpCompress(CompressionState &state_p, Vector &scan_vector, idx_t count) {
	auto &state = (AlpCompressionState<T> &)state_p;
	UnifiedVectorFormat vdata;
	scan_vector.ToUnifiedFormat(count, vdata);
	state.Append(vdata, count);
}

template <class T>
void AlpFinalizeCompress(CompressionState &state_p) {
	auto &state = (AlpCompressionState<T> &)state_p;
	state.Finalize();
}

} // namespace duckdb

//===----------------------------------------------------------------------===//
//                         DuckDB
//
// duckdb/common/types/row/tuple_data_allocator.hpp
//
//
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb/common/types/row/tuple_data_layout.hpp"
#include "duckdb/common/types/row/tuple_data_states.hpp"

namespace duckdb {

struct TupleDataSegment;
struct TupleDataChunk;
struct TupleDataChunkPart;
class ContinuousIdSet;

struct TupleDataBlock {
public:
	TupleDataBlock(BufferManager &buffer_manager, idx_t capacity_p);

	//! Disable copy constructors
	TupleDataBlock(const TupleDataBlock &other) = delete;
	TupleDataBlock &operator=(const TupleDataBlock &) = delete;

	//! Enable move constructors
	TupleDataBlock(TupleDataBlock &&other) noexcept;
	TupleDataBlock &operator=(TupleDataBlock &&) noexcept;

public:
	//! Remaining capacity (in bytes)
	idx_t RemainingCapacity() const {
		D_ASSERT(size <= capacity);
		return capacity - size;
	}

	//! Remaining capacity (in rows)
	idx_t RemainingCapacity(idx_t row_width) const {
		return RemainingCapacity() / row_width;
	}

public:
	//! The underlying row block
	shared_ptr<BlockHandle> handle;
	//! Capacity (in bytes)
	idx_t capacity;
	//! Occupied size (in bytes)
	idx_t size;
};

class TupleDataAllocator {
public:
	TupleDataAllocator(BufferManager &buffer_manager, shared_ptr<TupleDataLayout> &layout_ptr);
	TupleDataAllocator(TupleDataAllocator &allocator);

	~TupleDataAllocator();

	//! Get the buffer manager
	BufferManager &GetBufferManager();
	//! Get the buffer allocator
	Allocator &GetAllocator();
	//! Get the layout
	shared_ptr<TupleDataLayout> GetLayoutPtr() const;
	const TupleDataLayout &GetLayout() const;
	//! Number of row blocks
	idx_t RowBlockCount() const;
	//! Number of heap blocks
	idx_t HeapBlockCount() const;
	//! Sets the partition index of this tuple data allocator
	void SetPartitionIndex(idx_t index);

public:
	//! Builds out the chunks for next append, given the metadata in the append state
	void Build(TupleDataSegment &segment, TupleDataPinState &pin_state, TupleDataChunkState &chunk_state,
	           const idx_t append_offset, const idx_t append_count);
	bool BuildFastPath(TupleDataSegment &segment, TupleDataPinState &pin_state, TupleDataChunkState &chunk_state,
	                   const idx_t append_offset, const idx_t append_count);
	//! Initializes a chunk, making its pointers valid
	void InitializeChunkState(TupleDataSegment &segment, TupleDataPinState &pin_state, TupleDataChunkState &chunk_state,
	                          idx_t chunk_idx, bool init_heap);
	static void RecomputeHeapPointers(Vector &old_heap_ptrs, const SelectionVector &old_heap_sel,
	                                  const data_ptr_t row_locations[], Vector &new_heap_ptrs, const idx_t offset,
	                                  const idx_t count, const TupleDataLayout &layout, const idx_t base_col_offset);
	static void FindHeapPointers(TupleDataChunkState &chunk_state, SelectionVector &not_found, idx_t &not_found_count,
	                             const TupleDataLayout &layout, const idx_t base_col_offset);
	//! Releases or stores any handles in the management state that are no longer required
	void ReleaseOrStoreHandles(TupleDataPinState &state, TupleDataSegment &segment, TupleDataChunk &chunk,
	                           bool release_heap);
	//! Releases or stores ALL handles in the management state
	void ReleaseOrStoreHandles(TupleDataPinState &state, TupleDataSegment &segment);
	//! Sets 'can_destroy' to true for all blocks so they aren't added to the eviction queue
	void SetDestroyBufferUponUnpin();
	//! Destroy the blocks between the given indices
	void DestroyRowBlocks(idx_t row_block_begin, idx_t row_block_end);
	void DestroyHeapBlocks(idx_t heap_block_begin, idx_t heap_block_end);

private:
	//! Builds out a single part (grabs the lock)
	TupleDataChunkPart BuildChunkPart(TupleDataPinState &pin_state, TupleDataChunkState &chunk_state,
	                                  const idx_t append_offset, const idx_t append_count, TupleDataChunk &chunk);
	//! Internal function for InitializeChunkState
	void InitializeChunkStateInternal(TupleDataPinState &pin_state, TupleDataChunkState &chunk_state, idx_t offset,
	                                  bool recompute, bool init_heap_pointers, bool init_heap_sizes,
	                                  unsafe_vector<reference<TupleDataChunkPart>> &parts);
	//! Internal function for ReleaseOrStoreHandles
	static void ReleaseOrStoreHandlesInternal(TupleDataSegment &segment,
	                                          unsafe_vector<BufferHandle> &pinned_row_handles,
	                                          buffer_handle_map_t &handles, const ContinuousIdSet &block_ids,
	                                          unsafe_vector<TupleDataBlock> &blocks, TupleDataPinProperties properties);
	//! Pins the given row block
	BufferHandle &PinRowBlock(TupleDataPinState &state, const TupleDataChunkPart &part);
	//! Pins the given heap block
	BufferHandle &PinHeapBlock(TupleDataPinState &state, const TupleDataChunkPart &part);
	//! Gets the pointer to the rows for the given chunk part
	data_ptr_t GetRowPointer(TupleDataPinState &state, const TupleDataChunkPart &part);
	//! Gets the base pointer to the heap for the given chunk part
	data_ptr_t GetBaseHeapPointer(TupleDataPinState &state, const TupleDataChunkPart &part);

private:
	//! The buffer manager
	BufferManager &buffer_manager;
	//! The layout of the data
	shared_ptr<TupleDataLayout> layout_ptr;
	const TupleDataLayout &layout;
	//! Partition index (optional, if partitioned)
	optional_idx partition_index;
	//! Blocks storing the fixed-size rows
	unsafe_vector<TupleDataBlock> row_blocks;
	//! Blocks storing the variable-size data of the fixed-size rows (e.g., string, list)
	unsafe_vector<TupleDataBlock> heap_blocks;

	//! Re-usable arrays used while building buffer space
	unsafe_vector<reference<TupleDataChunkPart>> chunk_parts;
	unsafe_vector<pair<idx_t, idx_t>> chunk_part_indices;
};

} // namespace duckdb

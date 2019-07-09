//===----------------------------------------------------------------------===//
//                         DuckDB
//
// storage/table/version_chunk.hpp
//
//
//===----------------------------------------------------------------------===//

#pragma once

#include "common/types/string_heap.hpp"
#include "storage/storage_lock.hpp"
#include "storage/table/segment_tree.hpp"
#include "storage/table/column_segment.hpp"

namespace duckdb {
class ColumnDefinition;
class DataTable;
class StorageManager;

struct VersionInfo;

struct ColumnPointer {
	//! The column segment
	ColumnSegment *segment;
	//! The offset inside the column segment
	index_t offset;
};

class VersionChunk : public SegmentBase {
public:
	VersionChunk(DataTable &table, index_t start);

	//! The table
	DataTable &table;
	//! Whether or not the part of the storage chunk is dirty
	bool is_dirty[STORAGE_CHUNK_VECTORS] = {0};
	//! Deleted
	bool deleted[STORAGE_CHUNK_SIZE] = {0};
	//! The version pointers
	VersionInfo *version_pointers[STORAGE_CHUNK_SIZE] = {nullptr};
	//! Pointers to the column segments
	unique_ptr<ColumnPointer[]> columns;
	//! The lock for the storage
	StorageLock lock;
	//! The string heap of the storage chunk
	StringHeap string_heap;

public:
	//! Get a poiner to the row of the specified column
	data_ptr_t GetPointerToRow(index_t col, index_t row);
	// Cleanup the version information of a tuple
	void Cleanup(VersionInfo *info);
	// Undo the changes made by a tuple
	void Undo(VersionInfo *info);
	//! Mark a specific segment of the storage chunk as dirty or not dirty
	void SetDirtyFlag(index_t start, index_t count, bool dirty);
	//! Returns true if the specific segment of the storage chunk is dirty
	bool IsDirty(index_t start, index_t count);
};

} // namespace duckdb

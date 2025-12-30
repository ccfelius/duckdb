#pragma once

#include "duckdb/execution/index/bound_index.hpp"
#include "duckdb/execution/index/art/node.hpp"
#include "duckdb/common/array.hpp"

namespace duckdb {
class DUMMY_INDEX : public BoundIndex {
public:
	friend class Leaf;

public:
	//! Index type name for the DUMMY.
	static constexpr const char *TYPE_NAME = "DUMMY";
	//! FixedSizeAllocator count of the DUMMY
	static constexpr uint8_t ALLOCATOR_COUNT = 9;
	//! Keys must not exceed MAX_KEY_LEN * prefix_count.
	static constexpr idx_t MAX_KEY_LEN = 8192;

public:
	DUMMY_INDEX(const string &name, const IndexConstraintType index_constraint_type,
	            const duckdb::vector<column_t> &column_ids, TableIOManager &table_io_manager,
	            const duckdb::vector<duckdb::unique_ptr<Expression>> &unbound_expressions, AttachedDatabase &db,
	            const duckdb::shared_ptr<array<unsafe_unique_ptr<FixedSizeAllocator>, ALLOCATOR_COUNT>>
	                &allocators_ptr = nullptr,
	            const IndexStorageInfo &info = IndexStorageInfo());

	~DUMMY_INDEX() override = default;

	//! Create an index instance of this type.
	static duckdb::unique_ptr<BoundIndex> Create(CreateIndexInput &input);
	static IndexType GetDummyIndexType();

public:
	bool Scan(IndexScanState &state, idx_t max_count, set<row_t> &row_ids);

	//! Appends data to the locked index.
	ErrorData Append(IndexLock &l, DataChunk &chunk, Vector &row_ids) override;
	//! Appends data to the locked index and verifies constraint violations.
	ErrorData Append(IndexLock &l, DataChunk &chunk, Vector &row_ids, IndexAppendInfo &info) override;

	//! Insert a chunk.
	ErrorData Insert(IndexLock &l, DataChunk &chunk, Vector &row_ids) override;
	//! Insert a chunk and verifies constraint violations.
	ErrorData Insert(IndexLock &l, DataChunk &data, Vector &row_ids, IndexAppendInfo &info) override;

	//! Verify that data can be appended to the index without a constraint violation.
	void VerifyAppend(DataChunk &chunk, IndexAppendInfo &info, optional_ptr<ConflictManager> manager) override;

	//! Delete a chunk from the ART.
	idx_t TryDelete(IndexLock &state, DataChunk &entries, Vector &row_identifiers,
	                optional_ptr<SelectionVector> deleted_sel, optional_ptr<SelectionVector> non_deleted_sel) override;
	//! Drop the ART.
	void CommitDrop(IndexLock &index_lock) override;

	//! Merge another ART into this ART. Both must be locked.
	//! FIXME: Return ARTConflictType instead of a boolean.
	bool MergeIndexes(IndexLock &state, BoundIndex &other_index) override;

	//! Vacuums the ART storage.
	void Vacuum(IndexLock &state) override;

	//! Serializes ART memory to disk and returns the ART storage information.
	IndexStorageInfo SerializeToDisk(QueryContext context, const case_insensitive_map_t<Value> &options) override;
	//! Serializes ART memory to the WAL and returns the ART storage information.
	IndexStorageInfo SerializeToWAL(const case_insensitive_map_t<Value> &options) override;

	//! Returns the in-memory usage of the ART.
	idx_t GetInMemorySize(IndexLock &index_lock) override;

	bool SupportsDeltaIndexes() const override;
	unique_ptr<BoundIndex> CreateDeltaIndex(DeltaIndexType delta_index_type) const override;

	//! Verifies the nodes.
	void Verify(IndexLock &l) override;
	//! Verifies that the node allocations match the node counts.
	void VerifyAllocations(IndexLock &l) override;
	//! Verifies the index buffers.
	void VerifyBuffers(IndexLock &l) override;

	//! Returns string representation of the ART.
	string ToString(IndexLock &l, bool display_ascii = false) override;

	//! Fixed-size allocators holding the ART nodes.
	shared_ptr<array<unsafe_unique_ptr<FixedSizeAllocator>, ALLOCATOR_COUNT>> allocators;

private:
	void VerifyConstraint(DataChunk &chunk, IndexAppendInfo &info, ConflictManager &manager) override;
	string GetConstraintViolationMessage(VerifyExistenceType verify_type, idx_t failed_index,
	                                     DataChunk &input) override;
};
} // namespace duckdb
  // namespace duckdb

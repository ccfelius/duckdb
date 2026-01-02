#include "duckdb/execution/index/dummy_index.hpp"
#include "duckdb/execution/index/art/art.hpp"
#include "duckdb/execution/index/index_type.hpp"
#include "duckdb/catalog/catalog_entry/duck_table_entry.hpp"
#include "duckdb/catalog/catalog_entry/duck_index_entry.hpp"
#include "duckdb/catalog/catalog_entry/table_catalog_entry.hpp"
#include "duckdb/execution/index/bound_index.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/database_manager.hpp"
#include "duckdb/storage/storage_manager.hpp"
#include "duckdb/storage/table/append_state.hpp"
#include "duckdb/common/exception/transaction_exception.hpp"
#include "duckdb/execution/index/art/art_operator.hpp"
#include <type_traits>

namespace duckdb {

static_assert(!std::is_abstract<duckdb::DUMMY_INDEX>::value, "DUMMY_INDEX is abstract");

DummyKey::DummyKey() : len(0) {
}

DummyKey::DummyKey(const data_ptr_t data, idx_t len) : len(len), data(data) {
}

DummyKey::DummyKey(ArenaAllocator &allocator, idx_t len) : len(len) {
	data = allocator.Allocate(len);
}

DUMMY_INDEX::DUMMY_INDEX(
    const string &name, const IndexConstraintType index_constraint_type, const vector<column_t> &column_ids,
    TableIOManager &table_io_manager, const vector<unique_ptr<Expression>> &unbound_expressions, AttachedDatabase &db,
    const shared_ptr<array<unsafe_unique_ptr<FixedSizeAllocator>, ALLOCATOR_COUNT>> &allocators_ptr,
    const IndexStorageInfo &info)
    : BoundIndex(name, DUMMY_INDEX::TYPE_NAME, index_constraint_type, column_ids, table_io_manager, unbound_expressions,
                 db) {
	// TODO: implement stuff
}

unique_ptr<BoundIndex> DUMMY_INDEX::Create(CreateIndexInput &input) {
	auto DUMMY_INDEX_index =
	    make_uniq<DUMMY_INDEX>(input.name, input.constraint_type, input.column_ids, input.table_io_manager,
	                           input.unbound_expressions, input.db, nullptr, input.storage_info);
	return std::move(DUMMY_INDEX_index);
}

bool DUMMY_INDEX::Scan(IndexScanState &state, idx_t max_count, set<row_t> &row_ids) {
	return true;
}

//! Appends data to the locked index.
ErrorData DUMMY_INDEX::Append(IndexLock &l, DataChunk &chunk, Vector &row_ids) {
	return BoundIndex::Append(l, chunk, row_ids);
}
//! Appends data to the locked index and verifies constraint violations.
ErrorData DUMMY_INDEX::Append(IndexLock &l, DataChunk &chunk, Vector &row_ids, IndexAppendInfo &info) {
	return BoundIndex::Append(l, chunk, row_ids, info);
}

//! Insert a chunk.
ErrorData DUMMY_INDEX::Insert(IndexLock &l, DataChunk &chunk, Vector &row_ids) {
	return BoundIndex::Insert(l, chunk, row_ids);
}
//! Insert a chunk and verifies constraint violations.
ErrorData DUMMY_INDEX::Insert(IndexLock &l, DataChunk &data, Vector &row_ids, IndexAppendInfo &info) {
	return BoundIndex::Insert(l, data, row_ids, info);
}

//! Verify that data can be appended to the index without a constraint violation.
void DUMMY_INDEX::VerifyAppend(DataChunk &chunk, IndexAppendInfo &info, optional_ptr<ConflictManager> manager) {};

//! Delete a chunk from the ART.
idx_t DUMMY_INDEX::TryDelete(IndexLock &state, DataChunk &entries, Vector &row_identifiers,
                             optional_ptr<SelectionVector> deleted_sel, optional_ptr<SelectionVector> non_deleted_sel) {
	return 2;
};
//! Drop the ART.
void DUMMY_INDEX::CommitDrop(IndexLock &index_lock) {};

//! Merge another ART into this ART. Both must be locked.
//! FIXME: Return ARTConflictType instead of a boolean.
bool DUMMY_INDEX::MergeIndexes(IndexLock &state, BoundIndex &other_index) {
	return true;
};

//! Vacuums the ART storage.
void DUMMY_INDEX::Vacuum(IndexLock &state) {};

//! Serializes ART memory to disk and returns the ART storage information.
IndexStorageInfo DUMMY_INDEX::SerializeToDisk(QueryContext context, const case_insensitive_map_t<Value> &options) {
	return IndexStorageInfo();
}
//! Serializes ART memory to the WAL and returns the ART storage information.
IndexStorageInfo DUMMY_INDEX::SerializeToWAL(const case_insensitive_map_t<Value> &options) {
	return IndexStorageInfo();
}

//! Returns the in-memory usage of the ART.
idx_t DUMMY_INDEX::GetInMemorySize(IndexLock &index_lock) {
	return 0;
}

bool DUMMY_INDEX::SupportsDeltaIndexes() const {
	return false;
}
unique_ptr<BoundIndex> DUMMY_INDEX::CreateDeltaIndex(DeltaIndexType target_delta_index) const {
	auto constraint_type = index_constraint_type;
	if (target_delta_index == DeltaIndexType::DELETED_ROWS_IN_USE) {
		// deleted_rows_in_use allows duplicates regardless of whether or not the main index is a unique index or not
		constraint_type = IndexConstraintType::NONE;
	}
	auto result = make_uniq<ART>(name, constraint_type, GetColumnIds(), table_io_manager, unbound_expressions, db);
	result->delta_index_type = target_delta_index;
	return std::move(result);
}

//! Verifies the nodes.
void DUMMY_INDEX::Verify(IndexLock &l) {
}
//! Verifies that the node allocations match the node counts.
void DUMMY_INDEX::VerifyAllocations(IndexLock &l) {
}
//! Verifies the index buffers.
void DUMMY_INDEX::VerifyBuffers(IndexLock &l) {
}

//! Returns string representation of the ART.
string DUMMY_INDEX::ToString(IndexLock &l, bool display_ascii) {
	return "";
}

void VerifyConstraint(DataChunk &chunk, IndexAppendInfo &info, ConflictManager &manager) {
}

string GetConstraintViolationMessage(VerifyExistenceType verify_type, idx_t failed_index, DataChunk &input) {
	return "";
}

class DummyIndexBuildBindData : public IndexBuildBindData {
public:
	bool sorted = false;
};

unique_ptr<IndexBuildBindData> DummyIndexBuildBind(IndexBuildBindInput &input) {
	auto bind_data = make_uniq<DummyIndexBuildBindData>();

	// TODO: Verify that the the DUMMY_INDEX is applicable for the given columns and types.
	bind_data->sorted = true;
	if (input.expressions.size() > 1) {
		bind_data->sorted = false;
	} else if (input.expressions[0]->return_type.InternalType() == PhysicalType::VARCHAR) {
		bind_data->sorted = false;
	}

	return std::move(bind_data);
}

bool DummyIndexBuildSort(IndexBuildSortInput &input) {
	auto &bind_data = input.bind_data->Cast<DummyIndexBuildBindData>();
	return bind_data.sorted;
}

//----------------------------------------------------------------------------------------------------------------------
// Global State
//----------------------------------------------------------------------------------------------------------------------
class DummyIndexBuildGlobalState : public IndexBuildGlobalState {
public:
	unique_ptr<BoundIndex> global_index;
};

unique_ptr<IndexBuildGlobalState> DummyIndexBuildGlobalInit(IndexBuildInitGlobalStateInput &input) {
	auto state = make_uniq<DummyIndexBuildGlobalState>();

	auto &storage = input.table.GetStorage();
	state->global_index = make_uniq<DUMMY_INDEX>(input.info.index_name, input.info.constraint_type, input.storage_ids,
	                                             TableIOManager::Get(storage), input.expressions, storage.db);

	return std::move(state);
}

//----------------------------------------------------------------------------------------------------------------------
// Local State
//----------------------------------------------------------------------------------------------------------------------
class DummyIndexBuildLocalState : public IndexBuildLocalState {
public:
	unique_ptr<BoundIndex> local_index;
	ArenaAllocator arena_allocator;

	unsafe_vector<DummyKey> keys;
	unsafe_vector<DummyKey> row_ids;

	explicit DummyIndexBuildLocalState(ClientContext &context) : arena_allocator(Allocator::Get(context)) {};
};

unique_ptr<IndexBuildLocalState> DummyIndexBuildLocalInit(IndexBuildInitLocalStateInput &input) {
	// Create the local sink state and add the local index.
	auto state = make_uniq<DummyIndexBuildLocalState>(input.context);
	auto &storage = input.table.GetStorage();
	state->local_index = make_uniq<DUMMY_INDEX>(input.info.index_name, input.info.constraint_type, input.storage_ids,
	                                            TableIOManager::Get(storage), input.expressions, storage.db);

	// Initialize the local sink state.
	state->keys.resize(STANDARD_VECTOR_SIZE);
	state->row_ids.resize(STANDARD_VECTOR_SIZE);

	return std::move(state);
}

//----------------------------------------------------------------------------------------------------------------------
// Sink
//----------------------------------------------------------------------------------------------------------------------
void DummyIndexBuildSinkUnsorted(IndexBuildSinkInput &input, DataChunk &key_chunk, DataChunk &row_chunk) {
	auto &l_state = input.local_state.Cast<DummyIndexBuildLocalState>();
	auto row_count = key_chunk.size();
	auto &dummy_index = l_state.local_index->Cast<DUMMY_INDEX>();

	// Insert each key and its corresponding row ID.
	// for (idx_t i = 0; i < row_count; i++) {
	// 	auto status = dummy_index.tree.GetGateStatus();
	// 	auto conflict_type =
	// 		// do this still
	// 	    DummyIndexOperator::Insert(l_state.arena_allocator, DUMMY_INDEX, DUMMY_INDEX.tree, l_state.keys[i], 0,
	// 	                               l_state.row_ids[i], status, DeleteIndexInfo(), IndexAppendMode::DEFAULT);
	// 	D_ASSERT(conflict_type != DummyIndexConflictType::TRANSACTION);
	// 	if (conflict_type == DummyIndexConflictType::CONSTRAINT) {
	// 		throw ConstraintException("Data contains duplicates on indexed column(s)");
	// 	}
	// }
}

void DummyIndexBuildSinkSorted(IndexBuildSinkInput &input, DataChunk &key_chunk, DataChunk &row_chunk) {
	auto &l_state = input.local_state.Cast<DummyIndexBuildLocalState>();
	auto &storage = input.table.GetStorage();
	auto &l_index = l_state.local_index;

	// Construct a DUMMY_INDEX for this chunk.
	// auto dummy_index = make_uniq<DUMMY_INDEX>(
	    // input.info.index_name, l_index->GetConstraintType(), l_index->GetColumnIds(), l_index->table_io_manager,
	    // l_index->unbound_expressions, storage.db, l_index->Cast<DUMMY_INDEX>().allocators);
	    // if (dummy_index->Build(l_state.keys, l_state.row_ids, key_chunk.size()) !=
	    // DummyIndexConflictType::NO_CONFLICT) { 	throw ConstraintException("Data contains duplicates on indexed
	    // column(s)");
	    // }

	    // Merge the DUMMY_INDEX into the local DUMMY_INDEX.
	    // if (!l_index->MergeIndexes(*dummy_index)) {
	    // 	throw ConstraintException("Data contains duplicates on indexed column(s)");
	    // }
}

void DummyIndexBuildSink(IndexBuildSinkInput &input, DataChunk &key_chunk, DataChunk &row_chunk) {
	auto &bind_data = input.bind_data->Cast<DummyIndexBuildBindData>();
	auto &lstate = input.local_state.Cast<DummyIndexBuildLocalState>();

	lstate.arena_allocator.Reset();

	if (bind_data.sorted) {
		return DummyIndexBuildSinkSorted(input, key_chunk, row_chunk);
	}
	return DummyIndexBuildSinkUnsorted(input, key_chunk, row_chunk);
}

//----------------------------------------------------------------------------------------------------------------------
// Combine
//----------------------------------------------------------------------------------------------------------------------
void DummyIndexBuildCombine(IndexBuildCombineInput &input) {
	auto &gstate = input.global_state.Cast<DummyIndexBuildGlobalState>();
	auto &lstate = input.local_state.Cast<DummyIndexBuildLocalState>();

	if (!gstate.global_index->MergeIndexes(*lstate.local_index)) {
		throw ConstraintException("Data contains duplicates on indexed column(s)");
	}
}

//----------------------------------------------------------------------------------------------------------------------
// Finalize
//----------------------------------------------------------------------------------------------------------------------
unique_ptr<BoundIndex> DummyIndexBuildFinalize(IndexBuildFinalizeInput &input) {
	auto &gstate = input.global_state.Cast<DummyIndexBuildGlobalState>();
	return std::move(gstate.global_index);
}

// add a new index
IndexType DUMMY_INDEX::GetDummyIndexType() {
	IndexType dummy_index_type;
	dummy_index_type.name = DUMMY_INDEX::TYPE_NAME;
	dummy_index_type.create_instance = DUMMY_INDEX::Create;
	dummy_index_type.build_bind = DummyIndexBuildBind;
	dummy_index_type.build_sort = DummyIndexBuildSort;
	dummy_index_type.build_global_init = DummyIndexBuildGlobalInit;
	dummy_index_type.build_local_init = DummyIndexBuildLocalInit;
	dummy_index_type.build_sink = DummyIndexBuildSink;
	dummy_index_type.build_combine = DummyIndexBuildCombine;
	dummy_index_type.build_finalize = DummyIndexBuildFinalize;
	return dummy_index_type;
}

} // namespace duckdb

#include "dummy_index.hpp"
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
#include "duckdb/execution/index/index_key.hpp"
#include "duckdb/execution/index/art/art_operator.hpp"

namespace duckdb {

DUMMY_INDEX::DUMMY_INDEX(
    const string &name, const IndexConstraintType index_constraint_type, const vector<column_t> &column_ids,
    TableIOManager &table_io_manager, const vector<unique_ptr<Expression>> &unbound_expressions, AttachedDatabase &db,
    const shared_ptr<array<unsafe_unique_ptr<FixedSizeAllocator>, ALLOCATOR_COUNT>> &allocators_ptr,
    const IndexStorageInfo &info)
    : BoundIndex(name, ART::TYPE_NAME, index_constraint_type, column_ids, table_io_manager, unbound_expressions, db),

      DUMMY_INDEX::~DUMMY_INDEX() {
}

static duckdb::unique_ptr<DUMMY_INDEX> DUMMY_INDEX::Create(CreateIndexInput &input) {
	auto DUMMY_INDEX_index = make_uniq<DUMMY_INDEX>(input.constraint_type);
	return std::move(DUMMY_INDEX_index);
}

class DUMMY_INDEXBuildBindData : public IndexBuildBindData {
public:
	bool sorted = false;
};

unique_ptr<IndexBuildBindData> DummyIndexBuildBind(IndexBuildBindInput &input) {
	auto bind_data = make_uniq<DUMMY_INDEXBuildBindData>();

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
	auto &bind_data = input.bind_data->Cast<DUMMY_INDEXBuildBindData>();
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
	state->global_index = make_uniq<DUMMY_INDEX>(input.info.constraint_type);

	return std::move(state);
}

//----------------------------------------------------------------------------------------------------------------------
// Local State
//----------------------------------------------------------------------------------------------------------------------
class DUMMY_INDEXBuildLocalState : public IndexBuildLocalState {
public:
	unique_ptr<BoundIndex> local_index;
	ArenaAllocator arena_allocator;

	unsafe_vector<unique_ptr<IndexKey>> keys;
	unsafe_vector<unique_ptr<IndexKey>> row_ids;

	explicit DummyIndexBuildLocalState(ClientContext &context) : arena_allocator(Allocator::Get(context)) {};
};

unique_ptr<IndexBuildLocalState> DummyIndexBuildLocalInit(IndexBuildInitLocalStateInput &input) {
	// Create the local sink state and add the local index.
	auto state = make_uniq<DUMMY_INDEXBuildLocalState>(input.context);

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
void DUMMY_INDEXBuildSinkUnsorted(IndexBuildSinkInput &input, DataChunk &key_chunk, DataChunk &row_chunk) {
	auto &l_state = input.local_state.Cast<DUMMY_INDEXBuildLocalState>();
	auto row_count = key_chunk.size();
	auto &DUMMY_INDEX = l_state.local_index->Cast<DUMMY_INDEX>();

	// Insert each key and its corresponding row ID.
	for (idx_t i = 0; i < row_count; i++) {
		auto status = DUMMY_INDEX.tree.GetGateStatus();
		auto conflict_type =
		    DUMMY_INDEXOperator::Insert(l_state.arena_allocator, DUMMY_INDEX, DUMMY_INDEX.tree, l_state.keys[i], 0,
		                                l_state.row_ids[i], status, DeleteIndexInfo(), IndexAppendMode::DEFAULT);
		D_ASSERT(conflict_type != DUMMY_INDEXConflictType::TRANSACTION);
		if (conflict_type == DUMMY_INDEXConflictType::CONSTRAINT) {
			throw ConstraintException("Data contains duplicates on indexed column(s)");
		}
	}
}

void DummyIndexBuildSinkSorted(IndexBuildSinkInput &input, DataChunk &key_chunk, DataChunk &row_chunk) {
	auto &l_state = input.local_state.Cast<DUMMY_INDEXBuildLocalState>();
	auto &storage = input.table.GetStorage();
	auto &l_index = l_state.local_index;

	// Construct an DUMMY_INDEX for this chunk.
	auto DUMMY_INDEX = make_uniq<DUMMY_INDEX>(
	    input.info.index_name, l_index->GetConstraintType(), l_index->GetColumnIds(), l_index->table_io_manager,
	    l_index->unbound_expressions, storage.db, l_index->Cast<DUMMY_INDEX>().allocators);
	if (DUMMY_INDEX->Build(l_state.keys, l_state.row_ids, key_chunk.size()) != DUMMY_INDEXConflictType::NO_CONFLICT) {
		throw ConstraintException("Data contains duplicates on indexed column(s)");
	}

	// Merge the DUMMY_INDEX into the local DUMMY_INDEX.
	if (!l_index->MergeIndexes(*DUMMY_INDEX)) {
		throw ConstraintException("Data contains duplicates on indexed column(s)");
	}
}

void DUMMY_INDEXBuildSink(IndexBuildSinkInput &input, DataChunk &key_chunk, DataChunk &row_chunk) {
	auto &bind_data = input.bind_data->Cast<DUMMY_INDEXBuildBindData>();
	auto &lstate = input.local_state.Cast<DUMMY_INDEXBuildLocalState>();

	lstate.arena_allocator.Reset();

	lstate.local_index->Cast<DUMMY_INDEX>().GenerateKeyVectors(lstate.arena_allocator, key_chunk, row_chunk.data[0],
	                                                           lstate.keys, lstate.row_ids);

	if (bind_data.sorted) {
		return DUMMY_INDEXBuildSinkSorted(input, key_chunk, row_chunk);
	}
	return DUMMY_INDEXBuildSinkUnsorted(input, key_chunk, row_chunk);
}

//----------------------------------------------------------------------------------------------------------------------
// Combine
//----------------------------------------------------------------------------------------------------------------------
void DUMMY_INDEXBuildCombine(IndexBuildCombineInput &input) {
	auto &gstate = input.global_state.Cast<DUMMY_INDEXBuildGlobalState>();
	auto &lstate = input.local_state.Cast<DUMMY_INDEXBuildLocalState>();

	if (!gstate.global_index->MergeIndexes(*lstate.local_index)) {
		throw ConstraintException("Data contains duplicates on indexed column(s)");
	}
}

//----------------------------------------------------------------------------------------------------------------------
// Finalize
//----------------------------------------------------------------------------------------------------------------------
unique_ptr<BoundIndex> DUMMY_INDEXBuildFinalize(IndexBuildFinalizeInput &input) {
	auto &gstate = input.global_state.Cast<DUMMY_INDEXBuildGlobalState>();
	return std::move(gstate.global_index);
}

// add a new index
IndexType DUMMY_INDEX::GetDUMMY_INDEXIndexType() {
	IndexType DUMMY_INDEX_index_type;
	DUMMY_INDEX_index_type.name = DUMMY_INDEX::TYPE_NAME;
	DUMMY_INDEX_index_type.create_instance = DUMMY_INDEX::Create;
	DUMMY_INDEX_index_type.build_bind = DummyIndexBuildBind;
	DUMMY_INDEX_index_type.build_sort = DUMMY_INDEXBuildSort;
	DUMMY_INDEX_index_type.build_global_init = DUMMY_INDEXBuildGlobalInit;
	DUMMY_INDEX_index_type.build_local_init = DUMMY_INDEXBuildLocalInit;
	DUMMY_INDEX_index_type.build_sink = DUMMY_INDEXBuildSink;
	DUMMY_INDEX_index_type.build_combine = DUMMY_INDEXBuildCombine;
	DUMMY_INDEX_index_type.build_finalize = DUMMY_INDEXBuildFinalize;
	return DUMMY_INDEX_index_type;
}

} // namespace duckdb

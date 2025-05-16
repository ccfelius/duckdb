#include "duckdb/common/sorting/sorted_run.hpp"

#include "duckdb/common/types/row/tuple_data_collection.hpp"
#include "duckdb/common/sorting/sort_key.hpp"
#include "duckdb/common/types/row/block_iterator.hpp"

#include "pdqsort.h"
#include "ska_sort.hpp"
#include "vergesort.h"

namespace duckdb {

SortedRun::SortedRun(BufferManager &buffer_manager, shared_ptr<TupleDataLayout> key_layout,
                     shared_ptr<TupleDataLayout> payload_layout)
    : key_data(make_uniq<TupleDataCollection>(buffer_manager, std::move(key_layout))),
      payload_data(payload_layout->ColumnCount() != 0
                       ? make_uniq<TupleDataCollection>(buffer_manager, std::move(payload_layout))
                       : nullptr),
      finalized(false) {
	key_data->InitializeAppend(key_append_state, TupleDataPinProperties::KEEP_EVERYTHING_PINNED);
	if (payload_data) {
		payload_data->InitializeAppend(payload_append_state, TupleDataPinProperties::KEEP_EVERYTHING_PINNED);
	}
}

SortedRun::~SortedRun() {
}

template <SortKeyType SORT_KEY_TYPE>
static void TemplatedSetPayloadPointer(Vector &key_locations, Vector &payload_locations, const idx_t count) {
	using SORT_KEY = SortKey<SORT_KEY_TYPE>;

	const auto key_locations_ptr = FlatVector::GetData<SORT_KEY *>(key_locations);
	const auto payload_locations_ptr = FlatVector::GetData<data_ptr_t>(payload_locations);

	for (idx_t i = 0; i < count; i++) {
		key_locations_ptr[i]->SetPayload(payload_locations_ptr[i]);
	}
}

static void SetPayloadPointer(Vector &key_locations, Vector &payload_locations, const idx_t count,
                              const SortKeyType &sort_key_type) {
	switch (sort_key_type) {
	case SortKeyType::PAYLOAD_FIXED_16:
		return TemplatedSetPayloadPointer<SortKeyType::PAYLOAD_FIXED_16>(key_locations, payload_locations, count);
	case SortKeyType::PAYLOAD_FIXED_24:
		return TemplatedSetPayloadPointer<SortKeyType::PAYLOAD_FIXED_24>(key_locations, payload_locations, count);
	case SortKeyType::PAYLOAD_FIXED_32:
		return TemplatedSetPayloadPointer<SortKeyType::PAYLOAD_FIXED_32>(key_locations, payload_locations, count);
	case SortKeyType::PAYLOAD_VARIABLE_32:
		return TemplatedSetPayloadPointer<SortKeyType::PAYLOAD_VARIABLE_32>(key_locations, payload_locations, count);
	default:
		throw NotImplementedException("SetPayloadPointer for %s", EnumUtil::ToString(sort_key_type));
	}
}

void SortedRun::Sink(DataChunk &key, DataChunk &payload) {
	D_ASSERT(!finalized);
	key_data->Append(key_append_state, key);
	if (payload_data) {
		D_ASSERT(key.size() == payload.size());
		payload_data->Append(payload_append_state, payload);
		SetPayloadPointer(key_append_state.chunk_state.row_locations, payload_append_state.chunk_state.row_locations,
		                  key.size(), key_data->GetLayout().GetSortKeyType());
	}
}

template <class SORT_KEY>
struct ExtractKey {
	using result_type = uint64_t;
	const result_type &operator()(const SORT_KEY &key) const {
		return key.part0; // FIXME: this should only be used if there is a part0
	}
};

template <SortKeyType SORT_KEY_TYPE>
static void TemplatedSortThin(const TupleDataCollection &key_data) {
	D_ASSERT(SORT_KEY_TYPE == key_data.GetLayout().GetSortKeyType());
	using SORT_KEY = SortKey<SORT_KEY_TYPE>;
	using BLOCK_ITERATOR_STATE = BlockIteratorState<BlockIteratorStateType::IN_MEMORY>;
	using BLOCK_ITERATOR = block_iterator_t<const BLOCK_ITERATOR_STATE, SORT_KEY>;

	const BLOCK_ITERATOR_STATE state(key_data);
	auto begin = BLOCK_ITERATOR(state, 0);
	auto end = BLOCK_ITERATOR(state, key_data.Count());

	// Key is 8 bytes, use ska
	static const auto fallback = [](const BLOCK_ITERATOR &fb_begin, const BLOCK_ITERATOR &fb_end) {
		duckdb_ska_sort::ska_sort(fb_begin, fb_end, ExtractKey<SORT_KEY>());
	};
	duckdb_vergesort::vergesort(begin, end, std::less<SORT_KEY>(), fallback);
}

template <SortKeyType SORT_KEY_TYPE>
static void TemplatedSortWide(const TupleDataCollection &key_data) {
	D_ASSERT(SORT_KEY_TYPE == key_data.GetLayout().GetSortKeyType());
	using SORT_KEY = SortKey<SORT_KEY_TYPE>;
	using BLOCK_ITERATOR_STATE = BlockIteratorState<BlockIteratorStateType::IN_MEMORY>;
	using BLOCK_ITERATOR = block_iterator_t<const BLOCK_ITERATOR_STATE, SORT_KEY>;

	const BLOCK_ITERATOR_STATE state(key_data);
	auto begin = BLOCK_ITERATOR(state, 0);
	auto end = BLOCK_ITERATOR(state, key_data.Count());

	// Key is 8 bytes or more, start with ska
	static const auto fallback1 = [](const BLOCK_ITERATOR &fb_begin, const BLOCK_ITERATOR &fb_end) {
		duckdb_ska_sort::ska_sort(std::move(fb_begin), std::move(fb_end), ExtractKey<SORT_KEY>());
	};
	duckdb_vergesort::vergesort(begin, end, std::less<SORT_KEY>(), fallback1);

	// Finish with pdq
	static const auto fallback2 = [](const BLOCK_ITERATOR &fb_begin, const BLOCK_ITERATOR &fb_end) {
		duckdb_pdqsort::pdqsort_branchless(fb_begin, fb_end);
	};
	duckdb_vergesort::vergesort(begin, end, std::less<SORT_KEY>(), fallback2);
}

template <SortKeyType SORT_KEY_TYPE>
static void TemplatedSortVariable(const TupleDataCollection &key_data) {
	D_ASSERT(SORT_KEY_TYPE == key_data.GetLayout().GetSortKeyType());
	using SORT_KEY = SortKey<SORT_KEY_TYPE>;
	using BLOCK_ITERATOR_STATE = BlockIteratorState<BlockIteratorStateType::IN_MEMORY>;
	using BLOCK_ITERATOR = block_iterator_t<const BLOCK_ITERATOR_STATE, SORT_KEY>;

	const BLOCK_ITERATOR_STATE state(key_data);
	auto begin = BLOCK_ITERATOR(state, 0);
	auto end = BLOCK_ITERATOR(state, key_data.Count());

	// Variable key, use pdq
	static const auto fallback = [](const BLOCK_ITERATOR &fb_begin, const BLOCK_ITERATOR &fb_end) {
		duckdb_pdqsort::pdqsort_branchless(fb_begin, fb_end);
	};
	duckdb_vergesort::vergesort(begin, end, std::less<SORT_KEY>(), fallback);
}

static void Sort(const TupleDataCollection &key_data) {
	const auto sort_key_type = key_data.GetLayout().GetSortKeyType();
	switch (sort_key_type) {
	case SortKeyType::NO_PAYLOAD_FIXED_8:
		return TemplatedSortThin<SortKeyType::NO_PAYLOAD_FIXED_8>(key_data);
	case SortKeyType::NO_PAYLOAD_FIXED_16:
		return TemplatedSortWide<SortKeyType::NO_PAYLOAD_FIXED_16>(key_data);
	case SortKeyType::NO_PAYLOAD_FIXED_24:
		return TemplatedSortWide<SortKeyType::NO_PAYLOAD_FIXED_24>(key_data);
	case SortKeyType::NO_PAYLOAD_FIXED_32:
		return TemplatedSortWide<SortKeyType::NO_PAYLOAD_FIXED_32>(key_data);
	case SortKeyType::NO_PAYLOAD_VARIABLE_32:
		return TemplatedSortVariable<SortKeyType::NO_PAYLOAD_VARIABLE_32>(key_data);
	case SortKeyType::PAYLOAD_FIXED_16:
		return TemplatedSortThin<SortKeyType::PAYLOAD_FIXED_16>(key_data);
	case SortKeyType::PAYLOAD_FIXED_24:
		return TemplatedSortWide<SortKeyType::PAYLOAD_FIXED_24>(key_data);
	case SortKeyType::PAYLOAD_FIXED_32:
		return TemplatedSortWide<SortKeyType::PAYLOAD_FIXED_32>(key_data);
	case SortKeyType::PAYLOAD_VARIABLE_32:
		return TemplatedSortVariable<SortKeyType::PAYLOAD_VARIABLE_32>(key_data);
	default:
		throw NotImplementedException("TemplatedSort for %s", EnumUtil::ToString(sort_key_type));
	}
}

template <class SORT_KEY>
static void ReorderKeyData(TupleDataCollection &new_key_data, TupleDataAppendState &new_key_data_append_state,
                           TupleDataChunkState &input, const idx_t &count) {
	D_ASSERT(!SORT_KEY::CONSTANT_SIZE);
	const auto row_locations = FlatVector::GetData<const SORT_KEY *>(input.row_locations);
	const auto heap_locations = FlatVector::GetData<data_ptr_t>(input.heap_locations);
	const auto heap_sizes = FlatVector::GetData<idx_t>(input.heap_sizes);
	for (idx_t i = 0; i < count; i++) {
		const auto &sort_key = *row_locations[i];
		heap_locations[i] = sort_key.GetData();
		heap_sizes[i] = sort_key.GetHeapSize();
	}

	new_key_data_append_state.chunk_state.heap_sizes.Reference(input.heap_sizes);
	new_key_data.Build(new_key_data_append_state.pin_state, new_key_data_append_state.chunk_state, 0, count);
	new_key_data.CopyRows(new_key_data_append_state.chunk_state, input, *FlatVector::IncrementalSelectionVector(),
	                      count);
}

template <class SORT_KEY>
static void ReorderPayloadData(TupleDataCollection &new_payload_data,
                               TupleDataAppendState &new_payload_data_append_state, SORT_KEY *const *const key_ptrs,
                               TupleDataChunkState &input, const idx_t &count) {
	D_ASSERT(SORT_KEY::HAS_PAYLOAD);
	const auto row_locations = FlatVector::GetData<data_ptr_t>(input.row_locations);
	for (idx_t i = 0; i < count; i++) {
		const auto &sort_key = *key_ptrs[i];
		row_locations[i] = sort_key.GetPayload();
	}

	if (!new_payload_data.GetLayout().AllConstant()) {
		new_payload_data.FindHeapPointers(input, count);
	}
	new_payload_data_append_state.chunk_state.heap_sizes.Reference(input.heap_sizes);
	new_payload_data.Build(new_payload_data_append_state.pin_state, new_payload_data_append_state.chunk_state, 0,
	                       count);
	new_payload_data.CopyRows(new_payload_data_append_state.chunk_state, input,
	                          *FlatVector::IncrementalSelectionVector(), count);
}

template <SortKeyType SORT_KEY_TYPE>
static void TemplatedReorder(unique_ptr<TupleDataCollection> &key_data, unique_ptr<TupleDataCollection> &payload_data) {
	using SORT_KEY = SortKey<SORT_KEY_TYPE>;
	using BLOCK_ITERATOR_STATE = BlockIteratorState<BlockIteratorStateType::IN_MEMORY>;

	// Initialize new key data (if necessary)
	unique_ptr<TupleDataCollection> new_key_data;
	TupleDataAppendState new_key_data_append_state;
	if (!SORT_KEY::CONSTANT_SIZE) {
		new_key_data = key_data->CreateUnique();
		new_key_data->SetPartitionIndex(0); // We'll need the keys before the payload, this keeps them in memory longer
		new_key_data->InitializeAppend(new_key_data_append_state, TupleDataPinProperties::UNPIN_AFTER_DONE);
	}

	// Initialize new payload data (if necessary)
	unique_ptr<TupleDataCollection> new_payload_data;
	TupleDataAppendState new_payload_data_append_state;
	if (SORT_KEY::HAS_PAYLOAD) {
		new_payload_data = payload_data->CreateUnique();
		new_payload_data->InitializeAppend(new_payload_data_append_state, TupleDataPinProperties::UNPIN_AFTER_DONE);
	}

	// These states will be populated for appends
	TupleDataChunkState new_key_data_input;
	TupleDataChunkState new_payload_data_input;
	const auto key_ptrs = FlatVector::GetData<SORT_KEY *>(new_key_data_input.row_locations);

	// Iterate over sort keys
	const idx_t total_count = key_data->Count();
	const BLOCK_ITERATOR_STATE state(*key_data);
	auto it = block_iterator_t<const BLOCK_ITERATOR_STATE, SORT_KEY>(state, 0);

	idx_t index = 0;
	while (index < total_count) {
		const auto next = MinValue<idx_t>(total_count - index, STANDARD_VECTOR_SIZE);
		for (idx_t i = 0; i < next; i++) {
			key_ptrs[i] = &*it++;
		}
		if (!SORT_KEY::CONSTANT_SIZE) {
			ReorderKeyData<SORT_KEY>(*new_key_data, new_key_data_append_state, new_key_data_input, next);
		}
		if (SORT_KEY::HAS_PAYLOAD) {
			ReorderPayloadData<SORT_KEY>(*new_payload_data, new_payload_data_append_state, key_ptrs,
			                             new_payload_data_input, next);
		}
		index += next;
	}
	D_ASSERT(index == total_count);

	key_data->Unpin();
	if (!SORT_KEY::CONSTANT_SIZE) {
		new_key_data->FinalizePinState(new_key_data_append_state.pin_state);
		key_data = std::move(new_key_data);
	}

	if (SORT_KEY::HAS_PAYLOAD) {
		new_payload_data->FinalizePinState(new_payload_data_append_state.pin_state);
		new_payload_data->Unpin();
		payload_data = std::move(new_payload_data);
	}
}

static void Reorder(unique_ptr<TupleDataCollection> &key_data, unique_ptr<TupleDataCollection> &payload_data) {
	const auto sort_key_type = key_data->GetLayout().GetSortKeyType();
	switch (sort_key_type) {
	case SortKeyType::NO_PAYLOAD_VARIABLE_32:
		return TemplatedReorder<SortKeyType::NO_PAYLOAD_VARIABLE_32>(key_data, payload_data);
	case SortKeyType::PAYLOAD_FIXED_16:
		return TemplatedReorder<SortKeyType::PAYLOAD_FIXED_16>(key_data, payload_data);
	case SortKeyType::PAYLOAD_FIXED_24:
		return TemplatedReorder<SortKeyType::PAYLOAD_FIXED_24>(key_data, payload_data);
	case SortKeyType::PAYLOAD_FIXED_32:
		return TemplatedReorder<SortKeyType::PAYLOAD_FIXED_32>(key_data, payload_data);
	case SortKeyType::PAYLOAD_VARIABLE_32:
		return TemplatedReorder<SortKeyType::PAYLOAD_VARIABLE_32>(key_data, payload_data);
	default:
		throw NotImplementedException("TemplatedReorderPayload for %s", EnumUtil::ToString(sort_key_type));
	}
}

void SortedRun::Finalize(bool external) {
	D_ASSERT(!finalized);

	// Finalize the append
	key_data->FinalizePinState(key_append_state.pin_state);
	key_data->VerifyEverythingPinned();
	if (payload_data) {
		D_ASSERT(key_data->Count() == payload_data->Count());
		payload_data->FinalizePinState(payload_append_state.pin_state);
		payload_data->VerifyEverythingPinned();
	}

	// Sort the fixed-size portion of the keys
	Sort(*key_data);

	if (external) {
		// Reorder variable-size portion of keys and/or payload data (if necessary)
		const auto sort_key_type = key_data->GetLayout().GetSortKeyType();
		if (!SortKeyUtils::IsConstantSize(sort_key_type) || SortKeyUtils::HasPayload(sort_key_type)) {
			Reorder(key_data, payload_data);
		}
	}

	finalized = true;
}

void SortedRun::DestroyData(const idx_t tuple_idx_begin, const idx_t tuple_idx_end) {
	// We always have full chunks for sorting, so we can just use the vector size
	const auto chunk_idx_start = tuple_idx_begin / STANDARD_VECTOR_SIZE;
	const auto chunk_idx_end = tuple_idx_end / STANDARD_VECTOR_SIZE;
	if (chunk_idx_start == chunk_idx_end) {
		return;
	}
	key_data->DestroyChunks(chunk_idx_start, chunk_idx_end);
	if (payload_data) {
		payload_data->DestroyChunks(chunk_idx_start, chunk_idx_end);
	}
}

idx_t SortedRun::Count() const {
	return key_data->Count();
}

idx_t SortedRun::SizeInBytes() const {
	idx_t size = key_data->SizeInBytes();
	if (payload_data) {
		size += payload_data->SizeInBytes();
	}
	return size;
}

} // namespace duckdb

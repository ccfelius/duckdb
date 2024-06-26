#include "duckdb/common/types/column/partitioned_column_data.hpp"

#include "duckdb/common/hive_partitioning.hpp"
#include "duckdb/common/radix_partitioning.hpp"
#include "duckdb/storage/buffer_manager.hpp"

namespace duckdb {

PartitionedColumnData::PartitionedColumnData(PartitionedColumnDataType type_p, ClientContext &context_p,
                                             vector<LogicalType> types_p)
    : type(type_p), context(context_p), types(std::move(types_p)),
      allocators(make_shared_ptr<PartitionColumnDataAllocators>()) {
}

PartitionedColumnData::PartitionedColumnData(const PartitionedColumnData &other)
    : type(other.type), context(other.context), types(other.types), allocators(other.allocators) {
}

unique_ptr<PartitionedColumnData> PartitionedColumnData::CreateShared() {
	switch (type) {
	case PartitionedColumnDataType::RADIX:
		return make_uniq<RadixPartitionedColumnData>(Cast<RadixPartitionedColumnData>());
	default:
		throw NotImplementedException("CreateShared for this type of PartitionedColumnData");
	}
}

PartitionedColumnData::~PartitionedColumnData() {
}

void PartitionedColumnData::InitializeAppendState(PartitionedColumnDataAppendState &state) const {
	state.partition_sel.Initialize();
	state.slice_chunk.Initialize(BufferAllocator::Get(context), types);
	InitializeAppendStateInternal(state);
}

bool PartitionedColumnData::UseFixedSizeMap() const {
	return MaxPartitionIndex() < PartitionedTupleDataAppendState::MAP_THRESHOLD;
}

unique_ptr<DataChunk> PartitionedColumnData::CreatePartitionBuffer() const {
	auto result = make_uniq<DataChunk>();
	result->Initialize(BufferAllocator::Get(context), types, BufferSize());
	return result;
}

// LCOV_EXCL_START
template <class MAP_TYPE>
struct UnorderedMapGetter {
	static inline const typename MAP_TYPE::key_type &GetKey(typename MAP_TYPE::iterator &iterator) {
		return iterator->first;
	}

	static inline const typename MAP_TYPE::key_type &GetKey(const typename MAP_TYPE::const_iterator &iterator) {
		return iterator->first;
	}

	static inline typename MAP_TYPE::mapped_type &GetValue(typename MAP_TYPE::iterator &iterator) {
		return iterator->second;
	}

	static inline const typename MAP_TYPE::mapped_type &GetValue(const typename MAP_TYPE::const_iterator &iterator) {
		return iterator->second;
	}
};

template <class T>
struct FixedSizeMapGetter {
	static inline const idx_t &GetKey(fixed_size_map_iterator_t<T> &iterator) {
		return iterator.GetKey();
	}

	static inline const idx_t &GetKey(const const_fixed_size_map_iterator_t<T> &iterator) {
		return iterator.GetKey();
	}

	static inline T &GetValue(fixed_size_map_iterator_t<T> &iterator) {
		return iterator.GetValue();
	}

	static inline const T &GetValue(const const_fixed_size_map_iterator_t<T> &iterator) {
		return iterator.GetValue();
	}
};
// LCOV_EXCL_STOP

void PartitionedColumnData::Append(PartitionedColumnDataAppendState &state, DataChunk &input) {
	// Compute partition indices and store them in state.partition_indices
	ComputePartitionIndices(state, input);

	// Build the selection vector for the partitions
	BuildPartitionSel(state, input.size(), UseFixedSizeMap());

	// Early out: check if everything belongs to a single partition
	optional_idx partition_index;
	if (UseFixedSizeMap()) {
		if (state.fixed_partition_entries.size() == 1) {
			partition_index = state.fixed_partition_entries.begin().GetKey();
		}
	} else {
		if (state.partition_entries.size() == 1) {
			partition_index = state.partition_entries.begin()->first;
		}
	}

	// Early out: check if everything belongs to a single partition
	if (partition_index.IsValid()) {
		auto &partition = *partitions[partition_index.GetIndex()];
		auto &partition_append_state = *state.partition_append_states[partition_index.GetIndex()];
		partition.Append(partition_append_state, input);
		return;
	}

	if (UseFixedSizeMap()) {
		AppendInternal<fixed_size_map_t<list_entry_t>, FixedSizeMapGetter<list_entry_t>>(state, input,
		                                                                                 state.fixed_partition_entries);
	} else {
		AppendInternal<perfect_map_t<list_entry_t>, UnorderedMapGetter<perfect_map_t<list_entry_t>>>(
		    state, input, state.partition_entries);
	}
}

void PartitionedColumnData::BuildPartitionSel(PartitionedColumnDataAppendState &state, const idx_t append_count,
                                              const bool use_fixed_size_map) {
	if (use_fixed_size_map) {
		BuildPartitionSel<fixed_size_map_t<list_entry_t>, FixedSizeMapGetter<list_entry_t>>(
		    state, state.fixed_partition_entries, append_count);
	} else {
		BuildPartitionSel<perfect_map_t<list_entry_t>, UnorderedMapGetter<perfect_map_t<list_entry_t>>>(
		    state, state.partition_entries, append_count);
	}
}

template <class MAP_TYPE, class GETTER>
void PartitionedColumnData::BuildPartitionSel(PartitionedColumnDataAppendState &state, MAP_TYPE &partition_entries,
                                              const idx_t append_count) {
	const auto partition_indices = FlatVector::GetData<idx_t>(state.partition_indices);
	partition_entries.clear();

	switch (state.partition_indices.GetVectorType()) {
	case VectorType::FLAT_VECTOR:
		for (idx_t i = 0; i < append_count; i++) {
			const auto &partition_index = partition_indices[i];
			auto partition_entry = partition_entries.find(partition_index);
			if (partition_entry == partition_entries.end()) {
				partition_entries[partition_index] = list_entry_t(0, 1);
			} else {
				GETTER::GetValue(partition_entry).length++;
			}
		}
		break;
	case VectorType::CONSTANT_VECTOR:
		partition_entries[partition_indices[0]] = list_entry_t(0, append_count);
		break;
	default:
		throw InternalException("Unexpected VectorType in PartitionedTupleData::Append");
	}

	// Early out: check if everything belongs to a single partition
	if (partition_entries.size() == 1) {
		return;
	}

	// Compute offsets from the counts
	idx_t offset = 0;
	for (auto it = partition_entries.begin(); it != partition_entries.end(); ++it) {
		auto &partition_entry = GETTER::GetValue(it);
		partition_entry.offset = offset;
		offset += partition_entry.length;
	}

	// Now initialize a single selection vector that acts as a selection vector for every partition
	auto &partition_sel = state.partition_sel;
	for (idx_t i = 0; i < append_count; i++) {
		const auto &partition_index = partition_indices[i];
		auto &partition_offset = partition_entries[partition_index].offset;
		partition_sel[partition_offset++] = UnsafeNumericCast<sel_t>(i);
	}
}

template <class MAP_TYPE, class GETTER>
void PartitionedColumnData::AppendInternal(PartitionedColumnDataAppendState &state, DataChunk &input,
                                           const MAP_TYPE &partition_entries) {
	// Loop through the partitions to append the new data to the partition buffers, and flush the buffers if necessary
	SelectionVector partition_sel;
	for (auto it = partition_entries.begin(); it != partition_entries.end(); ++it) {
		const auto &partition_index = GETTER::GetKey(it);

		// Partition, buffer, and append state for this partition index
		auto &partition = *partitions[partition_index];
		auto &partition_buffer = *state.partition_buffers[partition_index];
		auto &partition_append_state = *state.partition_append_states[partition_index];

		// Length and offset into the selection vector for this chunk, for this partition
		const auto &partition_entry = GETTER::GetValue(it);
		const auto &partition_length = partition_entry.length;
		const auto partition_offset = partition_entry.offset - partition_length;

		// Create a selection vector for this partition using the offset into the single selection vector
		partition_sel.Initialize(state.partition_sel.data() + partition_offset);

		if (partition_length >= HalfBufferSize()) {
			// Slice the input chunk using the selection vector
			state.slice_chunk.Reset();
			state.slice_chunk.Slice(input, partition_sel, partition_length);

			// Append it to the partition directly
			partition.Append(partition_append_state, state.slice_chunk);
		} else {
			// Append the input chunk to the partition buffer using the selection vector
			partition_buffer.Append(input, false, &partition_sel, partition_length);

			if (partition_buffer.size() >= HalfBufferSize()) {
				// Next batch won't fit in the buffer, flush it to the partition
				partition.Append(partition_append_state, partition_buffer);
				partition_buffer.Reset();
				partition_buffer.SetCapacity(BufferSize());
			}
		}
	}
}

void PartitionedColumnData::FlushAppendState(PartitionedColumnDataAppendState &state) {
	for (idx_t i = 0; i < state.partition_buffers.size(); i++) {
		if (!state.partition_buffers[i]) {
			continue;
		}
		auto &partition_buffer = *state.partition_buffers[i];
		if (partition_buffer.size() > 0) {
			partitions[i]->Append(partition_buffer);
			partition_buffer.Reset();
		}
	}
}

void PartitionedColumnData::Combine(PartitionedColumnData &other) {
	// Now combine the state's partitions into this
	lock_guard<mutex> guard(lock);

	if (partitions.empty()) {
		// This is the first merge, we just copy them over
		partitions = std::move(other.partitions);
	} else {
		D_ASSERT(partitions.size() == other.partitions.size());
		// Combine the append state's partitions into this PartitionedColumnData
		for (idx_t i = 0; i < other.partitions.size(); i++) {
			if (!other.partitions[i]) {
				continue;
			}
			if (!partitions[i]) {
				partitions[i] = std::move(other.partitions[i]);
			} else {
				partitions[i]->Combine(*other.partitions[i]);
			}
		}
	}
}

vector<unique_ptr<ColumnDataCollection>> &PartitionedColumnData::GetPartitions() {
	return partitions;
}

void PartitionedColumnData::CreateAllocator() {
	allocators->allocators.emplace_back(make_shared_ptr<ColumnDataAllocator>(BufferManager::GetBufferManager(context)));
	allocators->allocators.back()->MakeShared();
}

} // namespace duckdb

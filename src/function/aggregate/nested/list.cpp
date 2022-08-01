#include "duckdb/common/pair.hpp"
#include "duckdb/common/types/chunk_collection.hpp"
#include "duckdb/function/aggregate/nested_functions.hpp"
#include "duckdb/planner/expression/bound_aggregate_expression.hpp"

namespace duckdb {

template <class T>
data_ptr_t ListFun::AllocatePrimitiveData(Allocator &allocator, vector<unique_ptr<AllocatedData>> &owning_vector,
                                          uint16_t &capacity) {

	owning_vector.emplace_back(allocator.Allocate(sizeof(ListSegment) + capacity * (sizeof(bool) + sizeof(T))));
	return owning_vector.back()->get();
}

data_ptr_t ListFun::AllocateListData(Allocator &allocator, vector<unique_ptr<AllocatedData>> &owning_vector,
                                     uint16_t &capacity) {

	owning_vector.emplace_back(
	    allocator.Allocate(sizeof(ListSegment) + capacity * (sizeof(bool) + sizeof(uint64_t)) + sizeof(LinkedList)));
	return owning_vector.back()->get();
}

data_ptr_t ListFun::AllocateStructData(Allocator &allocator, vector<unique_ptr<AllocatedData>> &owning_vector,
                                       uint16_t &capacity, idx_t child_count) {

	owning_vector.emplace_back(
	    allocator.Allocate(sizeof(ListSegment) + capacity * sizeof(bool) + child_count * sizeof(ListSegment *)));
	return owning_vector.back()->get();
}

template <class T>
T *ListFun::TemplatedGetPrimitiveData(ListSegment *segment) {
	return (T *)(((char *)segment) + sizeof(ListSegment) + segment->capacity * sizeof(bool));
}

uint64_t *ListFun::GetListLengthData(ListSegment *segment) {
	return (uint64_t *)(((char *)segment) + sizeof(ListSegment) + segment->capacity * sizeof(bool));
}

LinkedList *ListFun::GetListChildData(ListSegment *segment) {
	return (LinkedList *)(((char *)segment) + sizeof(ListSegment) +
	                      segment->capacity * (sizeof(bool) + sizeof(uint64_t)));
}

ListSegment **ListFun::GetStructData(ListSegment *segment) {
	return (ListSegment **)(((char *)segment) + sizeof(ListSegment) + segment->capacity * sizeof(bool));
}

void ListFun::GetPrimitiveDataValue(ListSegment *segment, const LogicalType &type, data_ptr_t &vector_data,
                                    idx_t &segment_idx, idx_t row_idx) {

	auto physical_type = type.InternalType();
	switch (physical_type) {
	case PhysicalType::BIT:
	case PhysicalType::BOOL: {
		auto data = TemplatedGetPrimitiveData<bool>(segment);
		((bool *)vector_data)[row_idx] = Load<bool>((data_ptr_t)(data + segment_idx));
		break;
	}
	case PhysicalType::INT8: {
		auto data = TemplatedGetPrimitiveData<int8_t>(segment);
		((int8_t *)vector_data)[row_idx] = Load<int8_t>((data_ptr_t)(data + segment_idx));
		break;
	}
	case PhysicalType::INT16: {
		auto data = TemplatedGetPrimitiveData<int16_t>(segment);
		((int16_t *)vector_data)[row_idx] = Load<int16_t>((data_ptr_t)(data + segment_idx));
		break;
	}
	case PhysicalType::INT32: {
		auto data = TemplatedGetPrimitiveData<int32_t>(segment);
		((int32_t *)vector_data)[row_idx] = Load<int32_t>((data_ptr_t)(data + segment_idx));
		break;
	}
	case PhysicalType::INT64: {
		auto data = TemplatedGetPrimitiveData<int64_t>(segment);
		((int64_t *)vector_data)[row_idx] = Load<int64_t>((data_ptr_t)(data + segment_idx));
		break;
	}
	case PhysicalType::UINT8: {
		auto data = TemplatedGetPrimitiveData<uint8_t>(segment);
		((uint8_t *)vector_data)[row_idx] = Load<uint8_t>((data_ptr_t)(data + segment_idx));
		break;
	}
	case PhysicalType::UINT16: {
		auto data = TemplatedGetPrimitiveData<uint16_t>(segment);
		((uint16_t *)vector_data)[row_idx] = Load<uint16_t>((data_ptr_t)(data + segment_idx));
		break;
	}
	case PhysicalType::UINT32: {
		auto data = TemplatedGetPrimitiveData<uint32_t>(segment);
		((uint32_t *)vector_data)[row_idx] = Load<uint32_t>((data_ptr_t)(data + segment_idx));
		break;
	}
	case PhysicalType::UINT64: {
		auto data = TemplatedGetPrimitiveData<uint64_t>(segment);
		((uint64_t *)vector_data)[row_idx] = Load<uint64_t>((data_ptr_t)(data + segment_idx));
		break;
	}
	case PhysicalType::FLOAT: {
		auto data = TemplatedGetPrimitiveData<float>(segment);
		((float *)vector_data)[row_idx] = Load<float>((data_ptr_t)(data + segment_idx));
		break;
	}
	case PhysicalType::DOUBLE: {
		auto data = TemplatedGetPrimitiveData<double>(segment);
		((double *)vector_data)[row_idx] = Load<double>((data_ptr_t)(data + segment_idx));
		break;
	}
	case PhysicalType::INT128: {
		auto data = TemplatedGetPrimitiveData<hugeint_t>(segment);
		((hugeint_t *)vector_data)[row_idx] = Load<hugeint_t>((data_ptr_t)(data + segment_idx));
		break;
	}
	case PhysicalType::INTERVAL: {
		auto data = TemplatedGetPrimitiveData<interval_t>(segment);
		((interval_t *)vector_data)[row_idx] = Load<interval_t>((data_ptr_t)(data + segment_idx));
		break;
	}
	default:
		throw InternalException("LIST aggregate not yet implemented for " + TypeIdToString(type.InternalType()));
	}
}

void ListFun::SetPrimitiveDataValue(ListSegment *segment, const LogicalType &type, data_ptr_t &input_data,
                                    idx_t &row_idx) {

	auto physical_type = type.InternalType();
	switch (physical_type) {
	case PhysicalType::BIT:
	case PhysicalType::BOOL: {
		auto data = TemplatedGetPrimitiveData<bool>(segment);
		Store<bool>(((bool *)input_data)[row_idx], (data_ptr_t)(data + segment->count));
		break;
	}
	case PhysicalType::INT8: {
		auto data = TemplatedGetPrimitiveData<int8_t>(segment);
		Store<int8_t>(((int8_t *)input_data)[row_idx], (data_ptr_t)(data + segment->count));
		break;
	}
	case PhysicalType::INT16: {
		auto data = TemplatedGetPrimitiveData<int16_t>(segment);
		Store<int16_t>(((int16_t *)input_data)[row_idx], (data_ptr_t)(data + segment->count));
		break;
	}
	case PhysicalType::INT32: {
		auto data = TemplatedGetPrimitiveData<int32_t>(segment);
		Store<int32_t>(((int32_t *)input_data)[row_idx], (data_ptr_t)(data + segment->count));
		break;
	}
	case PhysicalType::INT64: {
		auto data = TemplatedGetPrimitiveData<int64_t>(segment);
		Store<int64_t>(((int64_t *)input_data)[row_idx], (data_ptr_t)(data + segment->count));
		break;
	}
	case PhysicalType::UINT8: {
		auto data = TemplatedGetPrimitiveData<uint8_t>(segment);
		Store<uint8_t>(((uint8_t *)input_data)[row_idx], (data_ptr_t)(data + segment->count));
		break;
	}
	case PhysicalType::UINT16: {
		auto data = TemplatedGetPrimitiveData<uint16_t>(segment);
		Store<uint16_t>(((uint16_t *)input_data)[row_idx], (data_ptr_t)(data + segment->count));
		break;
	}
	case PhysicalType::UINT32: {
		auto data = TemplatedGetPrimitiveData<uint32_t>(segment);
		Store<uint32_t>(((uint32_t *)input_data)[row_idx], (data_ptr_t)(data + segment->count));
		break;
	}
	case PhysicalType::UINT64: {
		auto data = TemplatedGetPrimitiveData<uint64_t>(segment);
		Store<uint64_t>(((uint64_t *)input_data)[row_idx], (data_ptr_t)(data + segment->count));
		break;
	}
	case PhysicalType::FLOAT: {
		auto data = TemplatedGetPrimitiveData<float>(segment);
		Store<float>(((float *)input_data)[row_idx], (data_ptr_t)(data + segment->count));
		break;
	}
	case PhysicalType::DOUBLE: {
		auto data = TemplatedGetPrimitiveData<double>(segment);
		Store<double>(((double *)input_data)[row_idx], (data_ptr_t)(data + segment->count));
		break;
	}
	case PhysicalType::INT128: {
		auto data = TemplatedGetPrimitiveData<hugeint_t>(segment);
		Store<hugeint_t>(((hugeint_t *)input_data)[row_idx], (data_ptr_t)(data + segment->count));
		break;
	}
	case PhysicalType::INTERVAL: {
		auto data = TemplatedGetPrimitiveData<interval_t>(segment);
		Store<interval_t>(((interval_t *)input_data)[row_idx], (data_ptr_t)(data + segment->count));
		break;
	}
	default:
		throw InternalException("LIST aggregate not yet implemented for " + TypeIdToString(type.InternalType()));
	}
}

bool *ListFun::GetNullMask(ListSegment *segment) {
	return (bool *)(((char *)segment) + sizeof(ListSegment));
}

uint16_t ListFun::GetCapacityForNewSegment(LinkedList *linked_list) {

	// consecutive segments grow by the power of two
	uint16_t capacity = 4;
	if (linked_list->last_segment) {
		auto next_power_of_two = linked_list->last_segment->capacity * 2;
		capacity = next_power_of_two < 65536 ? next_power_of_two : linked_list->last_segment->capacity;
	}
	return capacity;
}

template <class T>
ListSegment *ListFun::TemplatedCreatePrimitiveSegment(Allocator &allocator,
                                                      vector<unique_ptr<AllocatedData>> &owning_vector,
                                                      uint16_t &capacity) {

	// allocate data and set the header
	auto segment = (ListSegment *)AllocatePrimitiveData<T>(allocator, owning_vector, capacity);
	segment->capacity = capacity;
	segment->count = 0;
	segment->next = nullptr;
	return segment;
}

ListSegment *ListFun::CreatePrimitiveSegment(Allocator &allocator, vector<unique_ptr<AllocatedData>> &owning_vector,
                                             uint16_t &capacity, const LogicalType &type) {

	auto physical_type = type.InternalType();

	switch (physical_type) {
	case PhysicalType::BIT:
	case PhysicalType::BOOL:
		return TemplatedCreatePrimitiveSegment<bool>(allocator, owning_vector, capacity);
	case PhysicalType::INT8:
		return TemplatedCreatePrimitiveSegment<int8_t>(allocator, owning_vector, capacity);
	case PhysicalType::INT16:
		return TemplatedCreatePrimitiveSegment<int16_t>(allocator, owning_vector, capacity);
	case PhysicalType::INT32:
		return TemplatedCreatePrimitiveSegment<int32_t>(allocator, owning_vector, capacity);
	case PhysicalType::INT64:
		return TemplatedCreatePrimitiveSegment<int64_t>(allocator, owning_vector, capacity);
	case PhysicalType::UINT8:
		return TemplatedCreatePrimitiveSegment<uint8_t>(allocator, owning_vector, capacity);
	case PhysicalType::UINT16:
		return TemplatedCreatePrimitiveSegment<uint16_t>(allocator, owning_vector, capacity);
	case PhysicalType::UINT32:
		return TemplatedCreatePrimitiveSegment<uint32_t>(allocator, owning_vector, capacity);
	case PhysicalType::UINT64:
		return TemplatedCreatePrimitiveSegment<uint64_t>(allocator, owning_vector, capacity);
	case PhysicalType::FLOAT:
		return TemplatedCreatePrimitiveSegment<float>(allocator, owning_vector, capacity);
	case PhysicalType::DOUBLE:
		return TemplatedCreatePrimitiveSegment<double>(allocator, owning_vector, capacity);
	case PhysicalType::VARCHAR:
		return TemplatedCreatePrimitiveSegment<char>(allocator, owning_vector, capacity);
	case PhysicalType::INT128:
		return TemplatedCreatePrimitiveSegment<hugeint_t>(allocator, owning_vector, capacity);
	case PhysicalType::INTERVAL:
		return TemplatedCreatePrimitiveSegment<interval_t>(allocator, owning_vector, capacity);
	default:
		throw InternalException("LIST aggregate not yet implemented for " + TypeIdToString(type.InternalType()));
	}
}

ListSegment *ListFun::CreateListSegment(Allocator &allocator, vector<unique_ptr<AllocatedData>> &owning_vector,
                                        uint16_t &capacity) {

	// allocate data and set the header
	auto segment = (ListSegment *)AllocateListData(allocator, owning_vector, capacity);
	segment->capacity = capacity;
	segment->count = 0;
	segment->next = nullptr;

	// create an empty linked list for the child vector
	auto linked_child_list = GetListChildData(segment);
	LinkedList linked_list(0, nullptr, nullptr);
	Store<LinkedList>(linked_list, (data_ptr_t)linked_child_list);

	return segment;
}

ListSegment *ListFun::CreateStructSegment(Allocator &allocator, vector<unique_ptr<AllocatedData>> &owning_vector,
                                          uint16_t &capacity, vector<unique_ptr<Vector>> &children) {

	// allocate data and set header
	auto segment = (ListSegment *)AllocateStructData(allocator, owning_vector, capacity, children.size());
	segment->capacity = capacity;
	segment->count = 0;
	segment->next = nullptr;

	// create a child ListSegment with exactly the same capacity for each child vector
	auto child_segments = GetStructData(segment);
	for (idx_t i = 0; i < children.size(); i++) {
		auto child_segment = CreateSegment(allocator, owning_vector, capacity, *children[i]);
		Store<ListSegment *>(child_segment, (data_ptr_t)(child_segments + i));
	}

	return segment;
}

ListSegment *ListFun::CreateSegment(Allocator &allocator, vector<unique_ptr<AllocatedData>> &owning_vector,
                                    uint16_t &capacity, Vector &input) {

	if (input.GetType().InternalType() == PhysicalType::VARCHAR) {
		return CreateListSegment(allocator, owning_vector, capacity);
	} else if (input.GetType().id() == LogicalTypeId::LIST) {
		return CreateListSegment(allocator, owning_vector, capacity);
	} else if (input.GetType().id() == LogicalTypeId::STRUCT) {
		auto &children = StructVector::GetEntries(input);
		return CreateStructSegment(allocator, owning_vector, capacity, children);
	}
	return CreatePrimitiveSegment(allocator, owning_vector, capacity, input.GetType());
}

ListSegment *ListFun::GetSegment(Allocator &allocator, vector<unique_ptr<AllocatedData>> &owning_vector,
                                 LinkedList *linked_list, Vector &input) {

	ListSegment *segment = nullptr;

	// determine segment
	if (!linked_list->last_segment) {
		// empty linked list, create the first (and last) segment
		auto capacity = GetCapacityForNewSegment(linked_list);
		segment = CreateSegment(allocator, owning_vector, capacity, input);
		linked_list->first_segment = segment;
		linked_list->last_segment = segment;

	} else if (linked_list->last_segment->capacity == linked_list->last_segment->count) {
		// the last segment of the linked list is full, create a new one and append it
		auto capacity = GetCapacityForNewSegment(linked_list);
		segment = CreateSegment(allocator, owning_vector, capacity, input);
		linked_list->last_segment->next = segment;
		linked_list->last_segment = segment;

	} else {
		// the last segment of the linked list is not full, append the data to it
		segment = linked_list->last_segment;
	}

	D_ASSERT(segment);
	return segment;
}

ListSegment *ListFun::GetCharSegment(Allocator &allocator, vector<unique_ptr<AllocatedData>> &owning_vector,
                                     LinkedList *linked_list) {

	ListSegment *segment = nullptr;

	// determine segment
	if (!linked_list->last_segment) {
		// empty linked list, create the first (and last) char segment
		auto capacity = GetCapacityForNewSegment(linked_list);
		segment = CreatePrimitiveSegment(allocator, owning_vector, capacity, LogicalTypeId::VARCHAR);
		linked_list->first_segment = segment;
		linked_list->last_segment = segment;

	} else if (linked_list->last_segment->capacity == linked_list->last_segment->count) {
		// the last segment of the linked list is full, create a new char segment and append it
		auto capacity = GetCapacityForNewSegment(linked_list);
		segment = CreatePrimitiveSegment(allocator, owning_vector, capacity, LogicalTypeId::VARCHAR);
		linked_list->last_segment->next = segment;
		linked_list->last_segment = segment;

	} else {
		// the last segment of the linked list is not full, append the data to it
		segment = linked_list->last_segment;
	}

	D_ASSERT(segment);
	return segment;
}

void ListFun::WriteDataToSegment(Allocator &allocator, vector<unique_ptr<AllocatedData>> &owning_vector,
                                 ListSegment *segment, Vector &input, idx_t &entry_idx, idx_t &count) {

	// get the vector data and the source index of the entry that we want to write
	UnifiedVectorFormat input_data;
	input.ToUnifiedFormat(count, input_data);
	auto source_idx = input_data.sel->get_index(entry_idx);

	// write null validity
	auto null_mask = GetNullMask(segment);
	auto is_null = !input_data.validity.RowIsValid(source_idx);
	null_mask[segment->count] = is_null;

	// write value
	if (input.GetType().InternalType() == PhysicalType::VARCHAR) {

		// set the length of this string
		auto str_length_data = GetListLengthData(segment);
		uint64_t str_length = 0;

		// get the string
		string str = "";
		if (!is_null) {
			auto str_t = ((string_t *)input_data.data)[source_idx];
			str_length = str_t.GetSize();
			str = str_t.GetString();
		}

		// we can reconstruct the offset from the length
		Store<uint64_t>(str_length, (data_ptr_t)(str_length_data + segment->count));

		if (!is_null) {
			// write the characters to the linked list of child segments
			auto child_segments = Load<LinkedList>((data_ptr_t)GetListChildData(segment));
			for (char &c : str) {
				auto child_segment = GetCharSegment(allocator, owning_vector, &child_segments);
				auto data = TemplatedGetPrimitiveData<char>(child_segment);
				data[child_segment->count] = c;
				child_segment->count++;
				child_segments.total_capacity++;
			}

			// store the updated linked list
			Store<LinkedList>(child_segments, (data_ptr_t)GetListChildData(segment));
		}

	} else if (input.GetType().id() == LogicalTypeId::LIST) {

		// set the length of this list
		auto list_length_data = GetListLengthData(segment);
		uint64_t list_length = 0;

		if (!is_null) {
			// get list entry information
			auto list_entries = (list_entry_t *)input_data.data;
			const auto &list_entry = list_entries[source_idx];
			list_length = list_entry.length;

			// get the child vector and its data
			auto lists_size = ListVector::GetListSize(input);
			auto &child_vector = ListVector::GetEntry(input);
			UnifiedVectorFormat child_data;
			child_vector.ToUnifiedFormat(lists_size, child_data);

			// loop over the child vector entries and recurse on them
			auto child_segments = Load<LinkedList>((data_ptr_t)GetListChildData(segment));
			for (idx_t child_idx = 0; child_idx < list_entry.length; child_idx++) {
				auto source_idx_child = child_data.sel->get_index(list_entry.offset + child_idx);
				AppendRow(allocator, owning_vector, &child_segments, child_vector, source_idx_child, lists_size);
			}
			// store the updated linked list
			Store<LinkedList>(child_segments, (data_ptr_t)GetListChildData(segment));
		}

		Store<uint64_t>(list_length, (data_ptr_t)(list_length_data + segment->count));

	} else if (input.GetType().id() == LogicalTypeId::STRUCT) {

		auto &children = StructVector::GetEntries(input);
		auto child_list = GetStructData(segment);

		// write the data of each of the children of the struct
		for (idx_t i = 0; i < children.size(); i++) {
			auto child_list_segment = Load<ListSegment *>((data_ptr_t)(child_list + i));
			WriteDataToSegment(allocator, owning_vector, child_list_segment, *children[i], source_idx, count);
			child_list_segment->count++;
		}

	} else {
		if (!is_null) {
			SetPrimitiveDataValue(segment, input.GetType(), input_data.data, source_idx);
		}
	}
}

void ListFun::AppendRow(Allocator &allocator, vector<unique_ptr<AllocatedData>> &owning_vector, LinkedList *linked_list,
                        Vector &input, idx_t &entry_idx, idx_t &count) {

	// FIXME: maybe faster if I first flatten all (nested) vectors in the update function?
	if (input.GetVectorType() == VectorType::DICTIONARY_VECTOR) {
		input.Flatten(count);
	}

	auto segment = GetSegment(allocator, owning_vector, linked_list, input);
	WriteDataToSegment(allocator, owning_vector, segment, input, entry_idx, count);

	linked_list->total_capacity++;
	segment->count++;
}

void ListFun::GetDataFromSegment(ListSegment *segment, Vector &result, idx_t &total_count) {

	auto &aggr_vector_validity = FlatVector::Validity(result);

	// set NULLs
	auto null_mask = GetNullMask(segment);
	for (idx_t i = 0; i < segment->count; i++) {
		if (null_mask[i]) {
			aggr_vector_validity.SetInvalid(total_count + i);
		}
	}

	if (result.GetType().InternalType() == PhysicalType::VARCHAR) {

		// append all the child chars to one string
		string str = "";
		auto linked_child_list = Load<LinkedList>((data_ptr_t)GetListChildData(segment));
		while (linked_child_list.first_segment) {
			auto child_segment = linked_child_list.first_segment;
			auto data = TemplatedGetPrimitiveData<char>(child_segment);
			str.append(data, child_segment->count);
			linked_child_list.first_segment = child_segment->next;
		}
		linked_child_list.last_segment = nullptr;

		// use length and (reconstructed) offset to get the correct substrings
		auto aggr_vector_data = FlatVector::GetData(result);
		auto str_length_data = GetListLengthData(segment);

		// get the substrings and write them to the result vector
		idx_t offset = 0;
		for (idx_t i = 0; i < segment->count; i++) {
			if (!null_mask[i]) {
				auto str_length = Load<uint64_t>((data_ptr_t)(str_length_data + i));
				auto substr = str.substr(offset, str_length);
				auto str_t = StringVector::AddStringOrBlob(result, substr);
				((string_t *)aggr_vector_data)[total_count + i] = str_t;
				offset += str_length;
			}
		}

	} else if (result.GetType().id() == LogicalTypeId::LIST) {

		auto list_vector_data = FlatVector::GetData<list_entry_t>(result);

		// get the starting offset
		idx_t offset = 0;
		if (total_count != 0) {
			offset = list_vector_data[total_count - 1].offset + list_vector_data[total_count - 1].length;
		}
		idx_t starting_offset = offset;

		// set length and offsets
		auto list_length_data = GetListLengthData(segment);
		for (idx_t i = 0; i < segment->count; i++) {
			auto list_length = Load<uint64_t>((data_ptr_t)(list_length_data + i));
			list_vector_data[total_count + i].length = list_length;
			list_vector_data[total_count + i].offset = offset;
			offset += list_length;
		}

		auto &child_vector = ListVector::GetEntry(result);
		auto linked_child_list = Load<LinkedList>((data_ptr_t)GetListChildData(segment));
		ListVector::Reserve(result, offset);

		// recurse into the linked list of child values
		BuildListVector(&linked_child_list, child_vector, starting_offset);

	} else if (result.GetType().id() == LogicalTypeId::STRUCT) {

		auto &children = StructVector::GetEntries(result);

		// recurse into the child segments of each child of the struct
		auto struct_children = GetStructData(segment);
		for (idx_t child_count = 0; child_count < children.size(); child_count++) {
			auto struct_children_segment = Load<ListSegment *>((data_ptr_t)(struct_children + child_count));
			GetDataFromSegment(struct_children_segment, *children[child_count], total_count);
		}

	} else {
		auto aggr_vector_data = FlatVector::GetData(result);

		// set values
		for (idx_t i = 0; i < segment->count; i++) {
			if (aggr_vector_validity.RowIsValid(total_count + i)) {
				GetPrimitiveDataValue(segment, result.GetType(), aggr_vector_data, i, total_count + i);
			}
		}
	}
}

void ListFun::BuildListVector(LinkedList *linked_list, Vector &result, idx_t &initial_total_count) {

	idx_t total_count = initial_total_count;
	while (linked_list->first_segment) {
		auto segment = linked_list->first_segment;
		GetDataFromSegment(segment, result, total_count);

		total_count += segment->count;
		linked_list->first_segment = segment->next;
	}

	linked_list->last_segment = nullptr;
}

void ListFun::InitializeValidities(Vector &vector, idx_t &capacity) {

	auto &validity_mask = FlatVector::Validity(vector);
	validity_mask.Initialize(capacity);

	if (vector.GetType().id() == LogicalTypeId::LIST) {
		auto &child_vector = ListVector::GetEntry(vector);
		InitializeValidities(child_vector, capacity);
	} else if (vector.GetType().id() == LogicalTypeId::STRUCT) {
		auto &children = StructVector::GetEntries(vector);
		for (auto &child : children) {
			InitializeValidities(*child, capacity);
		}
	}
}

struct ListAggState {
	LinkedList *linked_list;
	LogicalType *type;
	vector<unique_ptr<AllocatedData>> *owning_vector;
};

struct ListFunction {
	template <class STATE>
	static void Initialize(STATE *state) {
		state->linked_list = nullptr;
		state->type = nullptr;
		state->owning_vector = nullptr;
	}

	template <class STATE>
	static void Destroy(STATE *state) {
		D_ASSERT(state);
		if (state->linked_list) {
			delete state->linked_list;
			state->linked_list = nullptr;
		}
		if (state->type) {
			delete state->type;
			state->type = nullptr;
		}
		if (state->owning_vector) {
			state->owning_vector->clear();
			delete state->owning_vector;
			state->owning_vector = nullptr;
		}
	}
	static bool IgnoreNull() {
		return false;
	}
};

static void ListUpdateFunction(Vector inputs[], AggregateInputData &aggr_input_data, idx_t input_count,
                               Vector &state_vector, idx_t count) {
	D_ASSERT(input_count == 1);

	auto &input = inputs[0];
	UnifiedVectorFormat sdata;
	state_vector.ToUnifiedFormat(count, sdata);

	auto states = (ListAggState **)sdata.data;
	if (input.GetVectorType() == VectorType::SEQUENCE_VECTOR) {
		input.Flatten(count);
	}

	for (idx_t i = 0; i < count; i++) {
		auto state = states[sdata.sel->get_index(i)];
		if (!state->linked_list) {
			state->linked_list = new LinkedList(0, nullptr, nullptr);
			state->type = new LogicalType(input.GetType());
			state->owning_vector = new vector<unique_ptr<AllocatedData>>;
		}
		D_ASSERT(state->type);
		ListFun::AppendRow(aggr_input_data.allocator, *state->owning_vector, state->linked_list, input, i, count);
	}
}

static void ListCombineFunction(Vector &state, Vector &combined, AggregateInputData &, idx_t count) {
	UnifiedVectorFormat sdata;
	state.ToUnifiedFormat(count, sdata);
	auto states_ptr = (ListAggState **)sdata.data;

	auto combined_ptr = FlatVector::GetData<ListAggState *>(combined);
	for (idx_t i = 0; i < count; i++) {
		auto state = states_ptr[sdata.sel->get_index(i)];
		if (!state->linked_list) {
			// NULL, no need to append.
			continue;
		}
		D_ASSERT(state->type);
		D_ASSERT(state->owning_vector);
		if (!combined_ptr[i]->linked_list) {

			// copy the linked list
			combined_ptr[i]->linked_list = new LinkedList(0, nullptr, nullptr);
			combined_ptr[i]->linked_list->first_segment = state->linked_list->first_segment;
			combined_ptr[i]->linked_list->last_segment = state->linked_list->last_segment;
			combined_ptr[i]->linked_list->total_capacity = state->linked_list->total_capacity;

			// copy the type
			combined_ptr[i]->type = new LogicalType(*state->type);

			// new owning_vector to hold the unique pointers
			combined_ptr[i]->owning_vector = new vector<unique_ptr<AllocatedData>>;

		} else {
			combined_ptr[i]->linked_list->last_segment->next = state->linked_list->first_segment;
			combined_ptr[i]->linked_list->last_segment = state->linked_list->last_segment;
			combined_ptr[i]->linked_list->total_capacity += state->linked_list->total_capacity;
		}

		// copy the owning vector (and its unique pointers to the allocated data)
		// FIXME: more efficient way of copying the unique pointers?
		auto &owning_vector = *state->owning_vector;
		for (idx_t j = 0; j < state->owning_vector->size(); j++) {
			combined_ptr[i]->owning_vector->push_back(move(owning_vector[j]));
		}
	}
}

static void ListFinalize(Vector &state_vector, AggregateInputData &, Vector &result, idx_t count, idx_t offset) {
	UnifiedVectorFormat sdata;
	state_vector.ToUnifiedFormat(count, sdata);
	auto states = (ListAggState **)sdata.data;

	D_ASSERT(result.GetType().id() == LogicalTypeId::LIST);

	auto &mask = FlatVector::Validity(result);
	auto result_data = FlatVector::GetData<list_entry_t>(result);
	size_t total_len = ListVector::GetListSize(result);

	for (idx_t i = 0; i < count; i++) {

		auto state = states[sdata.sel->get_index(i)];
		const auto rid = i + offset;
		if (!state->linked_list) {
			mask.SetInvalid(rid);
			continue;
		}

		// set the length and offset of this list in the result vector
		auto total_capacity = state->linked_list->total_capacity;
		result_data[rid].length = total_capacity;
		result_data[rid].offset = total_len;
		total_len += total_capacity;

		D_ASSERT(state->type);

		Vector aggr_vector(*state->type, total_capacity);
		// FIXME: this is a workaround because the constructor of a vector does not set the size
		// of the validity mask, and by default it is set to STANDARD_VECTOR_SIZE
		// ListVector::Reserve only increases the validity mask, if (to_reserve > capacity),
		// which will not be the case if the value passed to the constructor of aggr_vector
		// is greater than to_reserve
		ListFun::InitializeValidities(aggr_vector, total_capacity);

		idx_t total_count = 0;
		ListFun::BuildListVector(state->linked_list, aggr_vector, total_count);
		ListVector::Append(result, aggr_vector, total_capacity);

		// now destroy the state (for parallel destruction)
		ListFunction::Destroy<ListAggState>(state);
	}
}

unique_ptr<FunctionData> ListBindFunction(ClientContext &context, AggregateFunction &function,
                                          vector<unique_ptr<Expression>> &arguments) {
	D_ASSERT(arguments.size() == 1);
	function.return_type = LogicalType::LIST(arguments[0]->return_type);
	return nullptr;
}

void ListFun::RegisterFunction(BuiltinFunctions &set) {
	auto agg =
	    AggregateFunction("list", {LogicalType::ANY}, LogicalTypeId::LIST, AggregateFunction::StateSize<ListAggState>,
	                      AggregateFunction::StateInitialize<ListAggState, ListFunction>, ListUpdateFunction,
	                      ListCombineFunction, ListFinalize, nullptr, ListBindFunction,
	                      AggregateFunction::StateDestroy<ListAggState, ListFunction>, nullptr, nullptr);
	set.AddFunction(agg);
	agg.name = "array_agg";
	set.AddFunction(agg);
}

} // namespace duckdb

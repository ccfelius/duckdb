#include "duckdb/execution/index/art/leaf.hpp"

#include "duckdb/execution/index/art/art.hpp"
#include "duckdb/execution/index/art/art_node.hpp"
#include "duckdb/execution/index/art/art_key.hpp"
#include "duckdb/execution/index/art/leaf_segment.hpp"
#include "duckdb/storage/meta_block_writer.hpp"
#include "duckdb/storage/meta_block_reader.hpp"

namespace duckdb {

Leaf *Leaf::New(ART &art, ARTNode &node, const Key &key, const uint32_t &depth, const row_t &row_id) {

	node.SetPtr(art.leaves->New(), ARTNodeType::LEAF);

	auto leaf = art.leaves->Get<Leaf>(node.GetPtr());
	art.IncreaseMemorySize(sizeof(Leaf));

	// set the fields of the leaf
	leaf->count = 1;
	leaf->row_ids.inlined = row_id;

	// initialize the prefix
	D_ASSERT(key.len >= depth);
	leaf->prefix.Initialize(art, key, depth, key.len - depth);

	return leaf;
}

Leaf *Leaf::New(ART &art, ARTNode &node, const Key &key, const uint32_t &depth, const row_t *row_ids,
                const idx_t &count) {

	// inlined leaf
	D_ASSERT(count >= 1);
	if (count == 1) {
		return Leaf::New(art, node, key, depth, row_ids[0]);
	}

	node.SetPtr(art.leaves->New(), ARTNodeType::LEAF);

	auto leaf = art.leaves->Get<Leaf>(node.GetPtr());
	art.IncreaseMemorySize(sizeof(Leaf));

	// set the fields of the leaf
	leaf->count = 0;

	// copy the row IDs
	LeafSegment::New(art, leaf->row_ids.position);
	auto segment = LeafSegment::Initialize(art, leaf->row_ids.position);
	for (idx_t i = 0; i < count; i++) {
		segment = segment->Append(art, leaf->count, row_ids[i]);
	}

	// set the prefix
	D_ASSERT(key.len >= depth);
	leaf->prefix.Initialize(art, key, depth, key.len - depth);

	return leaf;
}

void Leaf::Free(ART &art, ARTNode &node) {

	D_ASSERT(node);
	D_ASSERT(!node.IsSwizzled());

	auto leaf = art.leaves->Get<Leaf>(node.GetPtr());

	// delete all leaf segments
	if (!leaf->IsInlined()) {
		auto position = leaf->row_ids.position;
		while (position != DConstants::INVALID_INDEX) {
			auto next_position = LeafSegment::Get(art, position)->next;
			art.DecreaseMemorySize(sizeof(LeafSegment));
			LeafSegment::Free(art, position);
			position = next_position;
		}
	}

	art.DecreaseMemorySize(sizeof(Leaf));
}

void Leaf::InitializeMerge(ART &art, const idx_t &buffer_count) {

	if (IsInlined()) {
		return;
	}

	auto segment = LeafSegment::Get(art, row_ids.position);
	D_ASSERT((row_ids.position & FixedSizeAllocator::BUFFER_ID_TO_ZERO) ==
	         ((row_ids.position + buffer_count) & FixedSizeAllocator::BUFFER_ID_TO_ZERO));
	row_ids.position += buffer_count;

	auto position = segment->next;
	while (position != DConstants::INVALID_INDEX) {
		D_ASSERT((segment->next & FixedSizeAllocator::BUFFER_ID_TO_ZERO) ==
		         ((segment->next + buffer_count) & FixedSizeAllocator::BUFFER_ID_TO_ZERO));
		segment->next += buffer_count;
		segment = LeafSegment::Get(art, position);
		position = segment->next;
	}
}

void Leaf::Merge(ART &art, ARTNode &other) {

	auto other_leaf = art.leaves->Get<Leaf>(other.GetPtr());

	// copy inlined row ID
	if (other_leaf->IsInlined()) {
		Insert(art, other_leaf->row_ids.inlined);
		ARTNode::Free(art, other);
		return;
	}

	// get the first segment to copy to
	LeafSegment *segment;
	if (IsInlined()) {
		// row ID was inlined, move to a new segment
		auto position = LeafSegment::New(art);
		segment = LeafSegment::Initialize(art, position);
		D_ASSERT(ARTNode::LEAF_SEGMENT_SIZE >= 1);
		segment->row_ids[0] = row_ids.inlined;
		row_ids.position = position;
	} else {
		// get the tail of the segments of this leaf
		segment = LeafSegment::Get(art, row_ids.position)->GetTail(art);
	}

	// initialize loop variables
	auto other_position = other_leaf->row_ids.position;
	auto remaining = other_leaf->count;

	// copy row IDs
	while (other_position != DConstants::INVALID_INDEX) {
		auto other_segment = LeafSegment::Get(art, other_position);
		auto copy_count = MinValue(ARTNode::LEAF_SEGMENT_SIZE, remaining);

		// copy the data
		for (idx_t i = 0; i < copy_count; i++) {
			segment = segment->Append(art, count, other_segment->row_ids[i]);
		}

		// adjust the loop variables
		other_position = other_segment->next;
		remaining -= copy_count;
	}
	D_ASSERT(remaining == 0);

	ARTNode::Free(art, other);
}

void Leaf::Insert(ART &art, const row_t &row_id) {

	if (count == 0) {
		row_ids.inlined = row_id;
		count++;
		return;
	}

	if (count == 1) {
		MoveInlinedToSegment(art);
	}

	// append to the tail
	auto first_segment = LeafSegment::Get(art, row_ids.position);
	first_segment->GetTail(art)->Append(art, count, row_id);
}

void Leaf::Remove(ART &art, const row_t &row_id) {

	if (count == 0) {
		return;
	}

	if (IsInlined()) {
		if (row_ids.inlined == row_id) {
			count--;
		}
		return;
	}

	// possibly inline the row ID
	if (count == 2) {
		auto segment = LeafSegment::Get(art, row_ids.position);
		if (segment->row_ids[0] != row_id && segment->row_ids[1] != row_id) {
			return;
		}

		auto temp_row_id = segment->row_ids[0] == row_id ? segment->row_ids[1] : segment->row_ids[0];

		art.DecreaseMemorySize(sizeof(LeafSegment));
		LeafSegment::Free(art, row_ids.position);
		row_ids.inlined = temp_row_id;
		count--;
		return;
	}

	// find the row ID, and the segment containing that row ID
	auto position = row_ids.position;
	auto copy_idx = FindRowId(art, position, row_id);
	if (copy_idx == (uint32_t)DConstants::INVALID_INDEX) {
		return;
	}
	copy_idx++;

	// iterate all remaining segments and move the row IDs one field to the left
	LeafSegment *prev_segment = nullptr;
	while (copy_idx < count) {

		D_ASSERT(position != DConstants::INVALID_INDEX);
		auto segment = LeafSegment::Get(art, position);

		// this segment has at least one element, and we need to copy it into the previous segment
		if (prev_segment) {
			prev_segment->row_ids[ARTNode::LEAF_SEGMENT_SIZE - 1] = segment->row_ids[0];
			copy_idx++;
		}

		// calculate the copy count
		auto copy_count = count - copy_idx;
		if (ARTNode::LEAF_SEGMENT_SIZE - 1 < copy_count) {
			copy_count = ARTNode::LEAF_SEGMENT_SIZE - 1;
		}

		// copy row IDs
		D_ASSERT((copy_idx % ARTNode::LEAF_SEGMENT_SIZE) != 0);
		for (idx_t i = copy_idx % ARTNode::LEAF_SEGMENT_SIZE; i <= copy_count; i++) {
			segment->row_ids[i - 1] = segment->row_ids[i];
			copy_idx++;
		}

		// adjust loop variables
		prev_segment = segment;
		position = segment->next;
	}

	// true, if we need to delete the last segment
	if (count % ARTNode::LEAF_SEGMENT_SIZE == 1) {
		position = row_ids.position;
		while (position != DConstants::INVALID_INDEX) {

			// get the segment succeeding the current segment
			auto segment = LeafSegment::Get(art, position);
			D_ASSERT(segment->next != DConstants::INVALID_INDEX);
			auto next_segment = LeafSegment::Get(art, segment->next);

			// the segment following next_segment is the tail of the segment list
			if (next_segment->next == DConstants::INVALID_INDEX) {
				art.DecreaseMemorySize(sizeof(LeafSegment));
				LeafSegment::Free(art, segment->next);
				segment->next = DConstants::INVALID_INDEX;
			}

			// adjust loop variables
			position = segment->next;
		}
	}
	count--;
}

row_t Leaf::GetRowId(ART &art, const idx_t &position) const {

	D_ASSERT(position < count);
	if (IsInlined()) {
		return row_ids.inlined;
	}

	// get the correct segment
	auto segment = LeafSegment::Get(art, row_ids.position);
	for (idx_t i = 0; i < position / ARTNode::LEAF_SEGMENT_SIZE; i++) {
		D_ASSERT(segment->next != DConstants::INVALID_INDEX);
		segment = LeafSegment::Get(art, segment->next);
	}

	return segment->row_ids[position % ARTNode::LEAF_SEGMENT_SIZE];
}

uint32_t Leaf::FindRowId(ART &art, idx_t &position, const row_t &row_id) const {

	D_ASSERT(!IsInlined());

	auto next_position = position;
	auto remaining = count;
	while (next_position != DConstants::INVALID_INDEX) {

		position = next_position;
		auto segment = LeafSegment::Get(art, next_position);
		auto search_count = MinValue(ARTNode::LEAF_SEGMENT_SIZE, remaining);

		// search in this segment
		for (idx_t i = 0; i < search_count; i++) {
			if (segment->row_ids[i] == row_id) {
				return count - remaining + i;
			}
		}

		// adjust loop variables
		remaining -= search_count;
		next_position = segment->next;
	}
	return (uint32_t)DConstants::INVALID_INDEX;
}

string Leaf::ToString(ART &art) const {

	if (IsInlined()) {
		return "Leaf (" + to_string(count) + "): [" + to_string(row_ids.inlined) + "]";
	}

	auto position = row_ids.position;
	auto remaining = count;
	string str = "";
	uint32_t this_count = 0;
	while (position != DConstants::INVALID_INDEX) {
		auto segment = LeafSegment::Get(art, position);
		auto to_string_count = ARTNode::LEAF_SEGMENT_SIZE < remaining ? ARTNode::LEAF_SEGMENT_SIZE : remaining;

		for (idx_t i = 0; i < to_string_count; i++) {
			str += ", " + to_string(segment->row_ids[i]);
			this_count++;
		}
		remaining -= to_string_count;
		position = segment->next;
	}
	return "Leaf (" + to_string(this_count) + ", " + to_string(count) + "): [" + str + "] \n";
}

BlockPointer Leaf::Serialize(ART &art, MetaBlockWriter &writer) const {

	// get pointer and write fields
	auto block_pointer = writer.GetBlockPointer();
	writer.Write(ARTNodeType::LEAF);
	writer.Write<uint32_t>(count);
	prefix.Serialize(art, writer);

	if (IsInlined()) {
		writer.Write(row_ids.inlined);
		return block_pointer;
	}

	D_ASSERT(row_ids.position != DConstants::INVALID_INDEX);
	auto position = row_ids.position;
	auto remaining = count;

	// iterate all leaf segments and write their row IDs
	while (position != DConstants::INVALID_INDEX) {
		auto segment = LeafSegment::Get(art, position);
		auto write_count = MinValue(ARTNode::LEAF_SEGMENT_SIZE, remaining);

		// write the row IDs
		for (idx_t i = 0; i < write_count; i++) {
			writer.Write(segment->row_ids[i]);
		}

		// adjust loop variables
		remaining -= write_count;
		position = segment->next;
	}
	D_ASSERT(remaining == 0);

	return block_pointer;
}

void Leaf::Deserialize(ART &art, MetaBlockReader &reader) {

	auto count_p = reader.Read<uint32_t>();
	prefix.Deserialize(art, reader);

	// inlined
	if (count_p == 1) {
		row_ids.inlined = reader.Read<row_t>();
		count = count_p;
		return;
	}

	// copy into segments
	LeafSegment::New(art, row_ids.position);
	auto segment = LeafSegment::Initialize(art, row_ids.position);
	for (idx_t i = 0; i < count_p; i++) {
		segment = segment->Append(art, count, reader.Read<uint8_t>());
	}
	D_ASSERT(count_p == count);
}

void Leaf::Vacuum(ART &art) {

	if (IsInlined()) {
		return;
	}

	// first position has special treatment because we don't obtain it from a leaf segment
	if (art.leaf_segments->NeedsVacuum(row_ids.position)) {
		row_ids.position = art.leaf_segments->Vacuum(row_ids.position);
	}

	auto position = row_ids.position;
	while (position != DConstants::INVALID_INDEX) {
		auto segment = LeafSegment::Get(art, position);
		if (segment->next != DConstants::INVALID_INDEX && art.leaf_segments->NeedsVacuum(segment->next)) {
			segment->next = art.leaf_segments->Vacuum(segment->next);
		}
		position = segment->next;
	}
}

void Leaf::MoveInlinedToSegment(ART &art) {

	D_ASSERT(IsInlined());

	auto position = LeafSegment::New(art);
	auto segment = LeafSegment::Initialize(art, position);

	// move row ID
	D_ASSERT(ARTNode::LEAF_SEGMENT_SIZE >= 1);
	segment->row_ids[0] = row_ids.inlined;
	row_ids.position = position;
}

} // namespace duckdb

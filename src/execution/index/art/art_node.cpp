#include "duckdb/execution/index/art/art_node.hpp"

#include "duckdb/common/swap.hpp"
#include "duckdb/storage/table_io_manager.hpp"
#include "duckdb/execution/index/art/art.hpp"
#include "duckdb/execution/index/art/prefix_segment.hpp"
#include "duckdb/execution/index/art/leaf_segment.hpp"
#include "duckdb/execution/index/art/prefix.hpp"
#include "duckdb/execution/index/art/leaf.hpp"
#include "duckdb/execution/index/art/node4.hpp"
#include "duckdb/execution/index/art/node16.hpp"
#include "duckdb/execution/index/art/node48.hpp"
#include "duckdb/execution/index/art/node256.hpp"
#include "duckdb/storage/meta_block_writer.hpp"
#include "duckdb/storage/meta_block_reader.hpp"

namespace duckdb {

//===--------------------------------------------------------------------===//
// Constructors / Destructors
//===--------------------------------------------------------------------===//

ARTNode::ARTNode() : SwizzleablePointer() {
}

ARTNode::ARTNode(MetaBlockReader &reader) : SwizzleablePointer(reader) {
}

void ARTNode::New(ART &art, ARTNode &node, const ARTNodeType type) {

	switch (type) {
	case ARTNodeType::PREFIX_SEGMENT:
		PrefixSegment::New(art, node);
		break;
	case ARTNodeType::LEAF_SEGMENT:
		LeafSegment::New(art, node);
		break;
	case ARTNodeType::NODE_4:
		Node4::New(art, node);
		break;
	case ARTNodeType::NODE_16:
		Node16::New(art, node);
		break;
	case ARTNodeType::NODE_48:
		Node48::New(art, node);
		break;
	case ARTNodeType::NODE_256:
		Node256::New(art, node);
		break;
	default:
		throw InternalException("Invalid node type for New.");
	}
}

void ARTNode::Free(ART &art, ARTNode &node) {

	// recursively free all nodes that are in-memory, and skip swizzled and empty nodes

	if (!node.IsSet()) {
		return;
	}

	if (!node.IsSwizzled()) {

		// free the nodes (and their children)
		switch (node.DecodeARTNodeType()) {
		case ARTNodeType::PREFIX_SEGMENT:
			art.prefix_segments->Free(node);
			break;
		case ARTNodeType::LEAF_SEGMENT:
			art.leaf_segments->Free(node);
			break;
		case ARTNodeType::LEAF:
			node.GetPrefix(art)->Free(art);
			Leaf::Free(art, node);
			art.leaves->Free(node);
			break;
		case ARTNodeType::NODE_4:
			node.GetPrefix(art)->Free(art);
			Node4::Free(art, node);
			art.n4_nodes->Free(node);
			break;
		case ARTNodeType::NODE_16:
			node.GetPrefix(art)->Free(art);
			Node16::Free(art, node);
			art.n16_nodes->Free(node);
			break;
		case ARTNodeType::NODE_48:
			node.GetPrefix(art)->Free(art);
			Node48::Free(art, node);
			art.n48_nodes->Free(node);
			break;
		case ARTNodeType::NODE_256:
			node.GetPrefix(art)->Free(art);
			Node256::Free(art, node);
			art.n256_nodes->Free(node);
			break;
		default:
			throw InternalException("Invalid node type for Free.");
		}
	}

	// overwrite with an empty ART node
	node.Reset();
}

//===--------------------------------------------------------------------===//
// Inserts
//===--------------------------------------------------------------------===//

void ARTNode::ReplaceChild(const ART &art, const idx_t position, const ARTNode child) {

	D_ASSERT(!IsSwizzled());

	switch (DecodeARTNodeType()) {
	case ARTNodeType::NODE_4:
		return Node4::Get(art, *this)->ReplaceChild(position, child);
	case ARTNodeType::NODE_16:
		return Node16::Get(art, *this)->ReplaceChild(position, child);
	case ARTNodeType::NODE_48:
		return Node48::Get(art, *this)->ReplaceChild(position, child);
	case ARTNodeType::NODE_256:
		return Node256::Get(art, *this)->ReplaceChild(position, child);
	default:
		throw InternalException("Invalid node type for ReplaceChild.");
	}
}

void ARTNode::InsertChild(ART &art, ARTNode &node, const uint8_t byte, const ARTNode child) {

	switch (node.DecodeARTNodeType()) {
	case ARTNodeType::NODE_4:
		return Node4::InsertChild(art, node, byte, child);
	case ARTNodeType::NODE_16:
		return Node16::InsertChild(art, node, byte, child);
	case ARTNodeType::NODE_48:
		return Node48::InsertChild(art, node, byte, child);
	case ARTNodeType::NODE_256:
		return Node256::InsertChild(art, node, byte, child);
	default:
		throw InternalException("Invalid node type for InsertChild.");
	}
}

//===--------------------------------------------------------------------===//
// Deletes
//===--------------------------------------------------------------------===//

void ARTNode::DeleteChild(ART &art, ARTNode &node, const idx_t position) {

	switch (node.DecodeARTNodeType()) {
	case ARTNodeType::NODE_4:
		return Node4::DeleteChild(art, node, position);
	case ARTNodeType::NODE_16:
		return Node16::DeleteChild(art, node, position);
	case ARTNodeType::NODE_48:
		return Node48::DeleteChild(art, node, position);
	case ARTNodeType::NODE_256:
		return Node256::DeleteChild(art, node, position);
	default:
		throw InternalException("Invalid node type for DeleteChild.");
	}
}

//===--------------------------------------------------------------------===//
// Get functions
//===--------------------------------------------------------------------===//

ARTNode *ARTNode::GetChild(ART &art, const idx_t position) const {

	D_ASSERT(!IsSwizzled());

	ARTNode *child;
	switch (DecodeARTNodeType()) {
	case ARTNodeType::NODE_4: {
		child = Node4::Get(art, *this)->GetChild(position);
		break;
	}
	case ARTNodeType::NODE_16: {
		child = Node16::Get(art, *this)->GetChild(position);
		break;
	}
	case ARTNodeType::NODE_48: {
		child = Node48::Get(art, *this)->GetChild(position);
		break;
	}
	case ARTNodeType::NODE_256: {
		child = Node256::Get(art, *this)->GetChild(position);
		break;
	}
	default:
		throw InternalException("Invalid node type for GetChild.");
	}

	// unswizzle the ART node before returning it
	if (child->IsSwizzled()) {
		child->Deserialize(art);
	}
	return child;
}

uint8_t ARTNode::GetKeyByte(const ART &art, const idx_t position) const {

	D_ASSERT(!IsSwizzled());

	switch (DecodeARTNodeType()) {
	case ARTNodeType::NODE_4:
		return Node4::Get(art, *this)->GetKeyByte(position);
	case ARTNodeType::NODE_16:
		return Node16::Get(art, *this)->GetKeyByte(position);
	case ARTNodeType::NODE_48:
		return Node48::Get(art, *this)->GetKeyByte(position);
	case ARTNodeType::NODE_256:
		return Node256::Get(art, *this)->GetKeyByte(position);
	default:
		throw InternalException("Invalid node type for GetKeyByte.");
	}
}

idx_t ARTNode::GetChildPosition(const ART &art, const uint8_t byte) const {

	D_ASSERT(!IsSwizzled());

	switch (DecodeARTNodeType()) {
	case ARTNodeType::NODE_4:
		return Node4::Get(art, *this)->GetChildPosition(byte);
	case ARTNodeType::NODE_16:
		return Node16::Get(art, *this)->GetChildPosition(byte);
	case ARTNodeType::NODE_48:
		return Node48::Get(art, *this)->GetChildPosition(byte);
	case ARTNodeType::NODE_256:
		return Node256::Get(art, *this)->GetChildPosition(byte);
	default:
		throw InternalException("Invalid node type for GetChildPosition.");
	}
}

idx_t ARTNode::GetChildPositionGreaterEqual(const ART &art, const uint8_t byte, bool &inclusive) const {

	D_ASSERT(!IsSwizzled());

	switch (DecodeARTNodeType()) {
	case ARTNodeType::NODE_4:
		return Node4::Get(art, *this)->GetChildPositionGreaterEqual(byte, inclusive);
	case ARTNodeType::NODE_16:
		return Node16::Get(art, *this)->GetChildPositionGreaterEqual(byte, inclusive);
	case ARTNodeType::NODE_48:
		return Node48::Get(art, *this)->GetChildPositionGreaterEqual(byte, inclusive);
	case ARTNodeType::NODE_256:
		return Node256::Get(art, *this)->GetChildPositionGreaterEqual(byte, inclusive);
	default:
		throw InternalException("Invalid node type for GetChildPositionGreaterEqual.");
	}
}

idx_t ARTNode::GetMinPosition(const ART &art) const {

	D_ASSERT(!IsSwizzled());

	switch (DecodeARTNodeType()) {
	case ARTNodeType::NODE_4:
		return Node4::Get(art, *this)->GetMinPosition();
	case ARTNodeType::NODE_16:
		return Node16::Get(art, *this)->GetMinPosition();
	case ARTNodeType::NODE_48:
		return Node48::Get(art, *this)->GetMinPosition();
	case ARTNodeType::NODE_256:
		return Node256::Get(art, *this)->GetMinPosition();
	default:
		throw InternalException("Invalid node type for GetMinPosition.");
	}
}

uint8_t ARTNode::GetNextPosition(const ART &art, idx_t &position) const {

	D_ASSERT(!IsSwizzled());

	switch (DecodeARTNodeType()) {
	case ARTNodeType::NODE_4:
		return Node4::Get(art, *this)->GetNextPosition(position);
	case ARTNodeType::NODE_16:
		return Node16::Get(art, *this)->GetNextPosition(position);
	case ARTNodeType::NODE_48:
		return Node48::Get(art, *this)->GetNextPosition(position);
	case ARTNodeType::NODE_256:
		return Node256::Get(art, *this)->GetNextPosition(position);
	default:
		throw InternalException("Invalid node type for GetNextPositionAndByte.");
	}
}

//===--------------------------------------------------------------------===//
// (De)serialization
//===--------------------------------------------------------------------===//

BlockPointer ARTNode::Serialize(ART &art, MetaBlockWriter &writer) {

	if (!IsSet()) {
		return {(block_id_t)DConstants::INVALID_INDEX, 0};
	}

	if (IsSwizzled()) {
		Deserialize(art);
	}

	switch (DecodeARTNodeType()) {
	case ARTNodeType::LEAF:
		return Leaf::Get(art, *this)->Serialize(art, writer);
	case ARTNodeType::NODE_4:
		return Node4::Get(art, *this)->Serialize(art, writer);
	case ARTNodeType::NODE_16:
		return Node16::Get(art, *this)->Serialize(art, writer);
	case ARTNodeType::NODE_48:
		return Node48::Get(art, *this)->Serialize(art, writer);
	case ARTNodeType::NODE_256:
		return Node256::Get(art, *this)->Serialize(art, writer);
	default:
		throw InternalException("Invalid node type for Serialize.");
	}
}

void ARTNode::Deserialize(ART &art) {

	MetaBlockReader reader(art.table_io_manager.GetIndexBlockManager(), buffer_id);
	reader.offset = offset;
	type = reader.Read<uint8_t>();
	swizzle_flag = 0;

	switch (DecodeARTNodeType()) {
	case ARTNodeType::LEAF:
		SetPtr(art.leaves->New());
		return Leaf::Get(art, *this)->Deserialize(art, reader);
	case ARTNodeType::NODE_4:
		SetPtr(art.n4_nodes->New());
		return Node4::Get(art, *this)->Deserialize(art, reader);
	case ARTNodeType::NODE_16:
		SetPtr(art.n16_nodes->New());
		return Node16::Get(art, *this)->Deserialize(art, reader);
	case ARTNodeType::NODE_48:
		SetPtr(art.n48_nodes->New());
		return Node48::Get(art, *this)->Deserialize(art, reader);
	case ARTNodeType::NODE_256:
		SetPtr(art.n256_nodes->New());
		return Node256::Get(art, *this)->Deserialize(art, reader);
	default:
		throw InternalException("Invalid node type for Deserialize.");
	}
}

//===--------------------------------------------------------------------===//
// Utility
//===--------------------------------------------------------------------===//

string ARTNode::ToString(ART &art) const {

	D_ASSERT(!IsSwizzled());

	if (DecodeARTNodeType() == ARTNodeType::LEAF) {
		return Leaf::Get(art, *this)->ToString(art);
	}

	string str = "Node" + to_string(GetCapacity()) + ": [";

	auto next_pos = DConstants::INVALID_INDEX;
	GetNextPosition(art, next_pos);
	while (next_pos != DConstants::INVALID_INDEX) {
		auto child = GetChild(art, next_pos);
		str += "(" + to_string(next_pos) + ", " + child->ToString(art) + ")";
		GetNextPosition(art, next_pos);
	}

	return str + "]";
}

idx_t ARTNode::GetCapacity() const {

	D_ASSERT(!IsSwizzled());

	switch (DecodeARTNodeType()) {
	case ARTNodeType::NODE_4:
		return ARTNode::NODE_4_CAPACITY;
	case ARTNodeType::NODE_16:
		return ARTNode::NODE_16_CAPACITY;
	case ARTNodeType::NODE_48:
		return ARTNode::NODE_48_CAPACITY;
	case ARTNodeType::NODE_256:
		return ARTNode::NODE_256_CAPACITY;
	default:
		throw InternalException("Invalid node type for GetCapacity.");
	}
}

Prefix *ARTNode::GetPrefix(ART &art) {

	if (IsSwizzled()) {
		Deserialize(art);
	}

	switch (DecodeARTNodeType()) {
	case ARTNodeType::LEAF:
		return &Leaf::Get(art, *this)->prefix;
	case ARTNodeType::NODE_4:
		return &Node4::Get(art, *this)->prefix;
	case ARTNodeType::NODE_16:
		return &Node16::Get(art, *this)->prefix;
	case ARTNodeType::NODE_48:
		return &Node48::Get(art, *this)->prefix;
	case ARTNodeType::NODE_256:
		return &Node256::Get(art, *this)->prefix;
	default:
		throw InternalException("Invalid node type for GetPrefix.");
	}
}

ARTNodeType ARTNode::GetARTNodeTypeByCount(const idx_t count) {

	if (count <= NODE_4_CAPACITY) {
		return ARTNodeType::NODE_4;
	} else if (count <= NODE_16_CAPACITY) {
		return ARTNodeType::NODE_16;
	} else if (count <= NODE_48_CAPACITY) {
		return ARTNodeType::NODE_48;
	}
	return ARTNodeType::NODE_256;
}

//===--------------------------------------------------------------------===//
// Merging
//===--------------------------------------------------------------------===//

void ARTNode::InitializeMerge(ART &art, const ARTFlags &flags) {

	if (!IsSet()) {
		return;
	}

	if (IsSwizzled()) {
		Deserialize(art);
	}

	// if not all prefixes are inlined
	if (flags.merge_buffer_counts[(uint8_t)ARTNodeType::PREFIX_SEGMENT - 1] != 0) {
		// initialize prefix segments
		GetPrefix(art)->InitializeMerge(art, flags.merge_buffer_counts[(uint8_t)ARTNodeType::PREFIX_SEGMENT - 1]);
	}

	auto type = DecodeARTNodeType();
	switch (type) {
	case ARTNodeType::LEAF:
		// if not all leaves are inlined
		if (flags.merge_buffer_counts[(uint8_t)ARTNodeType::LEAF_SEGMENT - 1] != 0) {
			// initialize leaf segments
			Leaf::Get(art, *this)
			    ->InitializeMerge(art, flags.merge_buffer_counts[(uint8_t)ARTNodeType::LEAF_SEGMENT - 1]);
		}
		break;
	case ARTNodeType::NODE_4:
		Node4::Get(art, *this)->InitializeMerge(art, flags);
		break;
	case ARTNodeType::NODE_16:
		Node16::Get(art, *this)->InitializeMerge(art, flags);
		break;
	case ARTNodeType::NODE_48:
		Node48::Get(art, *this)->InitializeMerge(art, flags);
		break;
	case ARTNodeType::NODE_256:
		Node256::Get(art, *this)->InitializeMerge(art, flags);
		break;
	default:
		throw InternalException("Invalid node type for InitializeMerge.");
	}

	buffer_id += flags.merge_buffer_counts[(uint8_t)type - 1];
}

bool ARTNode::Merge(ART &art, ARTNode &other) {

	if (!IsSet()) {
		*this = other;
		other = ARTNode();
		return true;
	}

	return ResolvePrefixes(art, other);
}

bool ARTNode::ResolvePrefixes(ART &art, ARTNode &other) {

	// NOTE: we always merge into the left ART

	D_ASSERT(IsSet());
	D_ASSERT(other.IsSet());

	// make sure that r_node has the longer (or equally long) prefix
	if (GetPrefix(art)->count > other.GetPrefix(art)->count) {
		swap(*this, other);
	}

	auto &l_node = *this;
	auto &r_node = other;
	auto l_prefix = l_node.GetPrefix(art);
	auto r_prefix = r_node.GetPrefix(art);

	auto mismatch_position = l_prefix->MismatchPosition(art, *r_prefix);

	// both nodes have no prefix or the same prefix
	if (mismatch_position == l_prefix->count && l_prefix->count == r_prefix->count) {
		return MergeInternal(art, r_node);
	}

	if (mismatch_position == l_prefix->count) {
		// r_node's prefix contains l_node's prefix
		// l_node cannot be a leaf, otherwise the key represented by l_node would be a subset of another key
		// which is not possible by our construction
		D_ASSERT(l_node.DecodeARTNodeType() != ARTNodeType::LEAF);

		// test if the next byte (mismatch_position) in r_node (longer prefix) exists in l_node
		auto mismatch_byte = r_prefix->GetByte(art, mismatch_position);
		auto child_position = l_node.GetChildPosition(art, mismatch_byte);

		// update the prefix of r_node to only consist of the bytes after mismatch_position
		r_prefix->Reduce(art, mismatch_position);

		// insert r_node as a child of l_node at empty position
		if (child_position == DConstants::INVALID_INDEX) {

			ARTNode::InsertChild(art, l_node, mismatch_byte, r_node);
			r_node = ARTNode();
			return true;
		}

		// recurse
		auto child_node = l_node.GetChild(art, child_position);
		return child_node->ResolvePrefixes(art, r_node);
	}

	// prefixes differ, create new node and insert both nodes as children

	// create new node
	auto old_l_node = l_node;
	auto new_n4 = Node4::New(art, l_node);
	new_n4->prefix.Initialize(art, *l_prefix, mismatch_position);

	// insert old l_node, break up prefix of old l_node
	auto key_byte = l_prefix->Reduce(art, mismatch_position);
	Node4::InsertChild(art, l_node, key_byte, old_l_node);

	// insert r_node, break up prefix of r_node
	key_byte = r_prefix->Reduce(art, mismatch_position);
	Node4::InsertChild(art, l_node, key_byte, r_node);

	r_node = ARTNode();
	return true;
}

bool ARTNode::MergeInternal(ART &art, ARTNode &other) {

	D_ASSERT(IsSet());
	D_ASSERT(other.IsSet());

	// always try to merge the smaller node into the bigger node
	// because maybe there is enough free space in the bigger node to fit the smaller one
	// without too much recursion
	if (this->DecodeARTNodeType() < other.DecodeARTNodeType()) {
		swap(*this, other);
	}

	ARTNode empty_node;
	auto &l_node = *this;
	auto &r_node = other;

	if (r_node.DecodeARTNodeType() == ARTNodeType::LEAF) {
		D_ASSERT(l_node.DecodeARTNodeType() == ARTNodeType::LEAF);

		if (art.IsUnique()) {
			return false;
		}

		Leaf::Get(art, *this)->Merge(art, r_node);
		return true;
	}

	uint8_t key_byte;
	idx_t r_child_position = DConstants::INVALID_INDEX;

	while (true) {
		key_byte = r_node.GetNextPosition(art, r_child_position);
		if (r_child_position == DConstants::INVALID_INDEX) {
			break;
		}
		auto r_child = r_node.GetChild(art, r_child_position);
		auto l_child_position = l_node.GetChildPosition(art, key_byte);

		if (l_child_position == DConstants::INVALID_INDEX) {
			// insert child at empty position
			ARTNode::InsertChild(art, l_node, key_byte, *r_child);
			r_node.ReplaceChild(art, r_child_position, empty_node);

		} else {
			// recurse
			auto l_child = l_node.GetChild(art, l_child_position);
			if (!l_child->ResolvePrefixes(art, *r_child)) {
				return false;
			}
		}
	}

	ARTNode::Free(art, r_node);
	return true;
}

//===--------------------------------------------------------------------===//
// Vacuum
//===--------------------------------------------------------------------===//

void ARTNode::Vacuum(ART &art, ARTNode &node, const ARTFlags &flags) {

	if (node.IsSwizzled()) {
		return;
	}

	// possibly vacuum prefix segments, if not all prefixes are inlined
	if (flags.vacuum_flags[(uint8_t)ARTNodeType::PREFIX_SEGMENT - 1] != 0) {
		// vacuum prefix segments
		node.GetPrefix(art)->Vacuum(art);
	}

	bool needs_vacuum = flags.vacuum_flags[node.type - 1];

	switch (node.DecodeARTNodeType()) {
	case ARTNodeType::LEAF: {
		if (needs_vacuum && art.leaves->NeedsVacuum(node)) {
			node.SetPtr(art.leaves->VacuumPointer(node));
		}
		// possibly vacuum leaf segments, if not all leaves are inlined
		if (flags.vacuum_flags[(uint8_t)ARTNodeType::LEAF_SEGMENT - 1] != 0) {
			Leaf::Get(art, node)->Vacuum(art);
		}
		return;
	}
	case ARTNodeType::NODE_4:
		if (needs_vacuum && art.n4_nodes->NeedsVacuum(node)) {
			node.SetPtr(art.n4_nodes->VacuumPointer(node));
		}
		return Node4::Get(art, node)->Vacuum(art, flags);
	case ARTNodeType::NODE_16:
		if (needs_vacuum && art.n16_nodes->NeedsVacuum(node)) {
			node.SetPtr(art.n16_nodes->VacuumPointer(node));
		}
		return Node16::Get(art, node)->Vacuum(art, flags);
	case ARTNodeType::NODE_48:
		if (needs_vacuum && art.n48_nodes->NeedsVacuum(node)) {
			node.SetPtr(art.n48_nodes->VacuumPointer(node));
		}
		return Node48::Get(art, node)->Vacuum(art, flags);
	case ARTNodeType::NODE_256:
		if (needs_vacuum && art.n256_nodes->NeedsVacuum(node)) {
			node.SetPtr(art.n256_nodes->VacuumPointer(node));
		}
		return Node256::Get(art, node)->Vacuum(art, flags);
	default:
		throw InternalException("Invalid node type for Vacuum.");
	}
}

} // namespace duckdb

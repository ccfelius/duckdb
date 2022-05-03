#include "duckdb/execution/index/art/node4.hpp"
#include "duckdb/execution/index/art/node16.hpp"
#include "duckdb/execution/index/art/art.hpp"
#include "duckdb/storage/meta_block_reader.hpp"

namespace duckdb {

Node4::Node4(size_t compression_length) : Node(NodeType::N4, compression_length) {
	memset(key, 0, sizeof(key));
	for (auto &child : children_ptrs) {
		child = nullptr;
	}
}

Node4::~Node4() {
	for (auto &child : children_ptrs) {
		if (child) {
			if (!IsSwizzled((uintptr_t)child)) {
				delete child;
			}
		}
	}
}

void Node4::ReplaceChildPointer(idx_t pos, Node *node) {
	children_ptrs[pos] = node;
}

idx_t Node4::GetChildPos(uint8_t k) {
	for (idx_t pos = 0; pos < count; pos++) {
		if (key[pos] == k) {
			return pos;
		}
	}
	return Node::GetChildPos(k);
}

idx_t Node4::GetChildGreaterEqual(uint8_t k, bool &equal) {
	for (idx_t pos = 0; pos < count; pos++) {
		if (key[pos] >= k) {
			if (key[pos] == k) {
				equal = true;
			} else {
				equal = false;
			}
			return pos;
		}
	}
	return Node::GetChildGreaterEqual(k, equal);
}

idx_t Node4::GetMin() {
	return 0;
}

idx_t Node4::GetNextPos(idx_t pos) {
	if (pos == DConstants::INVALID_INDEX) {
		return 0;
	}
	pos++;
	return pos < count ? pos : DConstants::INVALID_INDEX;
}

Node *Node4::GetChild(ART &art, idx_t pos) {
	D_ASSERT(pos < count);
	return Node::GetChildSwizzled(art, (uintptr_t)children_ptrs[pos]);
}

void Node4::Insert(Node *&node, uint8_t key_byte, Node *new_child) {
	Node4 *n = (Node4 *)node;

	// Insert leaf into inner node
	if (node->count < 4) {
		// Insert element
		idx_t pos = 0;
		while ((pos < node->count) && (n->key[pos] < key_byte)) {
			pos++;
		}
		if (n->children_ptrs[pos] != nullptr) {
			for (idx_t i = n->count; i > pos; i--) {
				n->key[i] = n->key[i - 1];
				n->children_ptrs[i] = n->children_ptrs[i - 1];
			}
		}
		n->key[pos] = key_byte;
		n->children_ptrs[pos] = new_child;
		n->count++;
	} else {
		// Grow to Node16
		auto new_node = new Node16(n->prefix_length);
		new_node->count = 4;
		CopyPrefix(node, new_node);
		for (idx_t i = 0; i < 4; i++) {
			new_node->key[i] = n->key[i];
			new_node->children[i] = n->children_ptrs[i];
			n->children_ptrs[i] = nullptr;
		}
		// Delete old node and replace it with new node
		delete node;
		node = new_node;
		Node16::Insert(node, key_byte, new_child);
	}
}

void Node4::Erase(Node *&node, int pos) {
	Node4 *n = (Node4 *)node;
	D_ASSERT(pos < n->count);
	// erase the child and decrease the count
	// FIXME need a swizzled node method for deletes
	if (!IsSwizzled((uintptr_t)n->children_ptrs[pos])) {
		delete n->children_ptrs[pos];
	}
	n->children_ptrs[pos] = nullptr;
	n->count--;
	// potentially move any children backwards
	for (; pos < n->count; pos++) {
		n->key[pos] = n->key[pos + 1];
		n->children_ptrs[pos] = n->children_ptrs[pos + 1];
	}
	// set any remaining nodes as nullptr
	for (; pos < 4; pos++) {
		n->children_ptrs[pos] = nullptr;
	}

	// This is a one way node
	if (n->count == 1) {
		// FIXME need to get the swizzled
		auto child_ref = n->children_ptrs[0];
		// concatenate prefixes
		auto new_length = node->prefix_length + child_ref->prefix_length + 1;
		// have to allocate space in our prefix array
		unique_ptr<uint8_t[]> new_prefix = unique_ptr<uint8_t[]>(new uint8_t[new_length]);

		// first move the existing prefix (if any)
		for (uint32_t i = 0; i < child_ref->prefix_length; i++) {
			new_prefix[new_length - (i + 1)] = child_ref->prefix[child_ref->prefix_length - (i + 1)];
		}
		// now move the current key as part of the prefix
		new_prefix[node->prefix_length] = n->key[0];
		// finally add the old prefix
		for (uint32_t i = 0; i < node->prefix_length; i++) {
			new_prefix[i] = node->prefix[i];
		}
		//! set new prefix and move the child
		child_ref->prefix = move(new_prefix);
		child_ref->prefix_length = new_length;
		n->children_ptrs[0] = nullptr;
		delete node;
		node = child_ref;
	}
}

std::pair<idx_t, idx_t> Node4::Serialize(ART &art, duckdb::MetaBlockWriter &writer) {
	// Iterate through children and annotate their offsets
	vector<std::pair<idx_t, idx_t>> child_offsets;
	for (auto &child_ptr : children_ptrs) {
		if (child_ptr) {
			child_ptr = GetChildSwizzled(art, (uintptr_t)child_ptr);
			child_offsets.push_back(child_ptr->Serialize(art, writer));
			//			if (!IsSwizzled((uintptr_t ) child_ptr)){
			//				// We have to write this big boy
			//				child_offsets.push_back(child_ptr->Serialize(art, writer));
			//			} else{
			//				auto child_node = GetChildSwizzled(art, (node) child_ptr)
			//				// FIXME Just rewrite same offsets?
			////				auto block_info =  GetSwizzledBlockInfo((uintptr_t ) child_ptr);
			////				child_offsets.emplace_back(block_info.first, block_info.second);
			//			}
		} else {
			child_offsets.emplace_back(DConstants::INVALID_INDEX, DConstants::INVALID_INDEX);
		}
	}
	auto block_id = writer.block->id;
	auto offset = writer.offset;
	// Write Node Type
	writer.Write(type);
	writer.Write(count);
	// Write compression Info
	writer.Write(prefix_length);
	for (idx_t i = 0; i < prefix_length; i++) {
		writer.Write(prefix[i]);
	}
	// Write Key values
	for (auto &key_v : key) {
		writer.Write(key_v);
	}
	// Write child offsets
	for (auto &offsets : child_offsets) {
		writer.Write(offsets.first);
		writer.Write(offsets.second);
	}
	return {block_id, offset};
}

Node4 *Node4::Deserialize(duckdb::MetaBlockReader &reader) {
	auto count = reader.Read<uint16_t>();
	auto prefix_length = reader.Read<uint32_t>();
	auto node4 = new Node4(prefix_length);
	node4->count = count;
	node4->prefix_length = prefix_length;
	for (idx_t i = 0; i < prefix_length; i++) {
		node4->prefix[i] = reader.Read<uint8_t>();
	}

	// Get Key values
	for (idx_t i = 0; i < 4; i++) {
		node4->key[i] = reader.Read<uint8_t>();
	}

	// Get Child offsets
	for (idx_t i = 0; i < 4; i++) {
		idx_t block_id = reader.Read<idx_t>();
		idx_t offset = reader.Read<idx_t>();
		node4->children_ptrs[i] = (Node *)(Node::GenerateSwizzledPointer(block_id, offset));
	}

	return node4;
}

} // namespace duckdb

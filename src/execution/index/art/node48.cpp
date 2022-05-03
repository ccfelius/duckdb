#include "duckdb/execution/index/art/node16.hpp"
#include "duckdb/execution/index/art/node48.hpp"
#include "duckdb/execution/index/art/node256.hpp"

namespace duckdb {

Node48::Node48(size_t compression_length) : Node(NodeType::N48, compression_length) {
	for (idx_t i = 0; i < 256; i++) {
		child_index[i] = Node::EMPTY_MARKER;
	}
	for (auto &child : children) {
		child = nullptr;
	}
}

Node48::~Node48() {
	for (auto &child : children) {
		if (child) {
			if (!IsSwizzled((uintptr_t)child)) {
				delete child;
			}
		}
	}
}

idx_t Node48::GetChildPos(uint8_t k) {
	if (child_index[k] == Node::EMPTY_MARKER) {
		return DConstants::INVALID_INDEX;
	} else {
		return k;
	}
}

idx_t Node48::GetChildGreaterEqual(uint8_t k, bool &equal) {
	for (idx_t pos = k; pos < 256; pos++) {
		if (child_index[pos] != Node::EMPTY_MARKER) {
			if (pos == k) {
				equal = true;
			} else {
				equal = false;
			}
			return pos;
		}
	}
	return Node::GetChildGreaterEqual(k, equal);
}

idx_t Node48::GetNextPos(idx_t pos) {
	for (pos == DConstants::INVALID_INDEX ? pos = 0 : pos++; pos < 256; pos++) {
		if (child_index[pos] != Node::EMPTY_MARKER) {
			return pos;
		}
	}
	return Node::GetNextPos(pos);
}

Node *Node48::GetChild(ART &art, idx_t pos) {
	D_ASSERT(child_index[pos] != Node::EMPTY_MARKER);
	return Node::GetChildSwizzled(art, (uintptr_t)children[child_index[pos]]);
}

idx_t Node48::GetMin() {
	for (idx_t i = 0; i < 256; i++) {
		if (child_index[i] != Node::EMPTY_MARKER) {
			return i;
		}
	}
	return DConstants::INVALID_INDEX;
}

void Node48::Insert(Node *&node, uint8_t key_byte, Node *child) {
	auto n = (Node48 *)node;

	// Insert leaf into inner node
	if (node->count < 48) {
		// Insert element
		idx_t pos = n->count;
		if (n->children[pos]) {
			// find an empty position in the node list if the current position is occupied
			pos = 0;
			while (n->children[pos]) {
				pos++;
			}
		}
		n->children[pos] = child;
		n->child_index[key_byte] = pos;
		n->count++;
	} else {
		// Grow to Node256
		auto new_node = new Node256(n->prefix_length);
		for (idx_t i = 0; i < 256; i++) {
			if (n->child_index[i] != Node::EMPTY_MARKER) {
				new_node->children[i] = n->children[n->child_index[i]];
				n->children[n->child_index[i]] = nullptr;
			}
		}
		new_node->count = n->count;
		CopyPrefix(n, new_node);
		delete node;
		node = new_node;
		Node256::Insert(node, key_byte, child);
	}
}

void Node48::ReplaceChildPointer(idx_t pos, Node *node) {
	children[child_index[pos]] = node;
}

void Node48::Erase(Node *&node, int pos) {
	auto n = (Node48 *)(node);

	if (!IsSwizzled((uintptr_t)n->children[n->child_index[pos]])) {
		delete n->children[n->child_index[pos]];
	}
	n->children[n->child_index[pos]] = nullptr;
	n->child_index[pos] = Node::EMPTY_MARKER;
	n->count--;
	if (node->count <= 12) {
		auto new_node = new Node16(n->prefix_length);
		CopyPrefix(n, new_node);
		for (idx_t i = 0; i < 256; i++) {
			if (n->child_index[i] != Node::EMPTY_MARKER) {
				new_node->key[new_node->count] = i;
				new_node->children[new_node->count++] = n->children[n->child_index[i]];
				n->children[n->child_index[i]] = nullptr;
			}
		}
		delete node;
		node = new_node;
	}
}

std::pair<idx_t, idx_t> Node48::Serialize(ART &art, duckdb::MetaBlockWriter &writer) {
	// Iterate through children and annotate their offsets
	vector<std::pair<idx_t, idx_t>> child_offsets;
	for (auto &child_ptr : children) {
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
	for (auto &key_v : child_index) {
		writer.Write(key_v);
	}
	// Write child offsets
	for (auto &offsets : child_offsets) {
		writer.Write(offsets.first);
		writer.Write(offsets.second);
	}
	return {block_id, offset};
}

Node48 *Node48::Deserialize(duckdb::MetaBlockReader &reader) {
	auto count = reader.Read<uint16_t>();
	auto prefix_length = reader.Read<uint32_t>();
	auto node48 = new Node48(prefix_length);
	node48->count = count;
	node48->prefix_length = prefix_length;

	for (idx_t i = 0; i < prefix_length; i++) {
		node48->prefix[i] = reader.Read<uint8_t>();
	}

	// Get Key values
	for (idx_t i = 0; i < 256; i++) {
		node48->child_index[i] = reader.Read<uint8_t>();
	}

	// Get Child offsets
	for (idx_t i = 0; i < 48; i++) {
		idx_t block_id = reader.Read<idx_t>();
		idx_t offset = reader.Read<idx_t>();
		node48->children[i] = (Node *)(Node::GenerateSwizzledPointer(block_id, offset));
	}
	return node48;
}

} // namespace duckdb

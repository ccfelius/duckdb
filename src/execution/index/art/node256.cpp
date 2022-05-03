#include "duckdb/execution/index/art/node48.hpp"
#include "duckdb/execution/index/art/node256.hpp"

namespace duckdb {

Node256::Node256(size_t compression_length) : Node(NodeType::N256, compression_length) {
	for (auto &child : children) {
		child = nullptr;
	}
}
Node256::~Node256() {
	for (auto &child : children) {
		if (child) {
			if (!IsSwizzled((uintptr_t)child)) {
				delete child;
			}
		}
	}
}

idx_t Node256::GetChildPos(uint8_t k) {
	if (children[k]) {
		return k;
	} else {
		return DConstants::INVALID_INDEX;
	}
}

idx_t Node256::GetChildGreaterEqual(uint8_t k, bool &equal) {
	for (idx_t pos = k; pos < 256; pos++) {
		if (children[pos]) {
			if (pos == k) {
				equal = true;
			} else {
				equal = false;
			}
			return pos;
		}
	}
	return DConstants::INVALID_INDEX;
}

idx_t Node256::GetMin() {
	for (idx_t i = 0; i < 256; i++) {
		if (children[i]) {
			return i;
		}
	}
	return DConstants::INVALID_INDEX;
}

void Node256::ReplaceChildPointer(idx_t pos, Node *node) {
	children[pos] = node;
}

idx_t Node256::GetNextPos(idx_t pos) {
	for (pos == DConstants::INVALID_INDEX ? pos = 0 : pos++; pos < 256; pos++) {
		if (children[pos]) {
			return pos;
		}
	}
	return Node::GetNextPos(pos);
}

Node *Node256::GetChild(ART &art, idx_t pos) {
	return Node::GetChildSwizzled(art, (uintptr_t)children[pos]);
}

void Node256::Insert(Node *&node, uint8_t key_byte, Node *child) {
	auto n = (Node256 *)(node);

	n->count++;
	n->children[key_byte] = child;
}

void Node256::Erase(Node *&node, int pos) {
	auto n = (Node256 *)(node);

	if (!IsSwizzled((uintptr_t)n->children[pos])) {
		delete n->children[pos];
	}
	n->children[pos] = nullptr;
	n->count--;
	if (node->count <= 36) {
		auto new_node = new Node48(n->prefix_length);
		CopyPrefix(n, new_node);
		for (idx_t i = 0; i < 256; i++) {
			if (n->children[i]) {
				new_node->child_index[i] = new_node->count;
				new_node->children[new_node->count] = n->children[i];
				n->children[i] = nullptr;
				new_node->count++;
			}
		}
		delete node;
		node = new_node;
	}
}

std::pair<idx_t, idx_t> Node256::Serialize(ART &art, duckdb::MetaBlockWriter &writer) {
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
	// Write child offsets
	for (auto &offsets : child_offsets) {
		writer.Write(offsets.first);
		writer.Write(offsets.second);
	}
	return {block_id, offset};
}

Node256 *Node256::Deserialize(duckdb::MetaBlockReader &reader) {
	auto count = reader.Read<uint16_t>();
	auto prefix_length = reader.Read<uint32_t>();
	auto node256 = new Node256(prefix_length);
	node256->count = count;
	node256->prefix_length = prefix_length;
	for (idx_t i = 0; i < prefix_length; i++) {
		node256->prefix[i] = reader.Read<uint8_t>();
	}

	// Get Child offsets
	for (idx_t i = 0; i < 256; i++) {
		node256->children[i] = (Node *)(Node::GenerateSwizzledPointer(reader.Read<idx_t>(), reader.Read<idx_t>()));
	}
	return node256;
}

} // namespace duckdb

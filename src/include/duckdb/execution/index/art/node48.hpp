//===----------------------------------------------------------------------===//
//                         DuckDB
//
// duckdb/execution/index/art/node48.hpp
//
//
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb/execution/index/fixed_size_allocator.hpp"
#include "duckdb/execution/index/art/art.hpp"
#include "duckdb/execution/index/art/node.hpp"

namespace duckdb {

//! Node48 holds up to 48 children. It contains a child_index array, which is indexed by the key
//! byte. It contains the position of the child node in the children array.
class Node48 {
public:
	static constexpr NType NODE_48 = NType::NODE_48;
	static constexpr uint8_t EMPTY_MARKER = Node::EMPTY_MARKER;
	static constexpr uint8_t CAPACITY = Node::NODE_48_CAPACITY;

public:
	Node48() = delete;
	Node48(const Node48 &) = delete;
	Node48 &operator=(const Node48 &) = delete;

	uint8_t count;
	uint8_t child_index[Node::NODE_256_CAPACITY];
	Node children[CAPACITY];

public:
	//! Get a new Node48 and initialize it.
	static Node48 &New(ART &art, Node &node);
	//! Free the node and its children.
	static void Free(ART &art, Node &node);

	//! Initializes all fields of the node while growing a Node16 to a Node48.
	static Node48 &GrowNode16(ART &art, Node &node48, Node &node16);
	//! Initializes all fields of the node while shrinking a Node256 to a Node48.
	static Node48 &ShrinkNode256(ART &art, Node &node48, Node &node256);

	//! Insert a child at byte.
	static void InsertChild(ART &art, Node &node, const uint8_t byte, const Node child);
	//! Delete the child at byte.
	static void DeleteChild(ART &art, Node &node, const uint8_t byte);
	//! Replace the child at byte.
	void ReplaceChild(const uint8_t byte, const Node child);

public:
	template <class F, class NODE>
	static void Iterator(NODE &n, F &&lambda) {
		for (idx_t i = 0; i < Node::NODE_256_CAPACITY; i++) {
			if (n.child_index[i] != EMPTY_MARKER) {
				lambda(n.children[n.child_index[i]]);
			}
		}
	}

	template <class NODE>
	static Node *GetChild(NODE &n, const uint8_t byte) {
		if (n.child_index[byte] != Node48::EMPTY_MARKER) {
			return &n.children[n.child_index[byte]];
		}
		return nullptr;
	}

	template <class NODE>
	static Node *GetNextChild(NODE &n, uint8_t &byte) {
		for (idx_t i = byte; i < Node::NODE_256_CAPACITY; i++) {
			if (n.child_index[i] != Node::EMPTY_MARKER) {
				byte = UnsafeNumericCast<uint8_t>(i);
				return &n.children[n.child_index[i]];
			}
		}
		return nullptr;
	}
};
} // namespace duckdb

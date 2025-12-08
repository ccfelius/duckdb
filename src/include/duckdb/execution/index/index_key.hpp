//===----------------------------------------------------------------------===//
//                         DuckDB
//
// duckdb/execution/index/index_key.hpp
//
//
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb/common/common.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/radix.hpp"
#include "duckdb/common/types/string_type.hpp"
#include "duckdb/common/types/value.hpp"
#include "duckdb/storage/arena_allocator.hpp"

namespace duckdb {

class IndexKey {
public:
	virtual ~IndexKey() {
	}

	IndexKey();
	IndexKey(data_ptr_t data, idx_t len);
	IndexKey(ArenaAllocator &allocator, idx_t len);

	idx_t len;
	data_ptr_t data;

public:
	template <class T>
	static inline IndexKey CreateIndexKey(ArenaAllocator &allocator, T value) {
		auto data = IndexKey::CreateData<T>(allocator, value);
		return IndexKey(data, sizeof(value));
	}

	template <class T>
	static inline IndexKey CreateIndexKey(ArenaAllocator &allocator, Value &value) {
		return CreateIndexKey(allocator, value.GetValueUnsafe<T>());
	}

	template <class T>
	static inline void CreateIndexKey(ArenaAllocator &allocator, IndexKey &key, T value) {
		key.data = IndexKey::CreateData<T>(allocator, value);
		key.len = sizeof(value);
	}

	template <class T>
	static inline void CreateIndexKey(ArenaAllocator &allocator, IndexKey &key, Value value) {
		key.data = IndexKey::CreateData<T>(allocator, value.GetValueUnsafe<T>());
		key.len = sizeof(value);
	}

	static IndexKey CreateKey(ArenaAllocator &allocator, PhysicalType type, Value &value);

public:
	data_t &operator[](idx_t i) {
		return data[i];
	}
	const data_t &operator[](idx_t i) const {
		return data[i];
	}
	bool operator>(const IndexKey &key) const;
	bool operator>=(const IndexKey &key) const;
	bool operator==(const IndexKey &key) const;

	inline bool ByteMatches(const IndexKey &other, idx_t depth) const {
		return data[depth] == other[depth];
	}
	inline bool Empty() const {
		return len == 0;
	}

	void Concat(ArenaAllocator &allocator, const IndexKey &other);
	row_t GetRowId() const;
	idx_t GetMismatchPos(const IndexKey &other, const idx_t start) const;
	void VerifyKeyLength(const idx_t max_len) const;

private:
	template <class T>
	static inline data_ptr_t CreateData(ArenaAllocator &allocator, T value) {
		auto data = allocator.Allocate(sizeof(value));
		Radix::EncodeData<T>(data, value);
		return data;
	}
};

template <>
IndexKey IndexKey::CreateIndexKey(ArenaAllocator &allocator, string_t value);
template <>
IndexKey IndexKey::CreateIndexKey(ArenaAllocator &allocator, const char *value);
template <>
void IndexKey::CreateIndexKey(ArenaAllocator &allocator, IndexKey &key, string_t value);

} // namespace duckdb

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

	DUCKDB_API IndexKey() = default;
	DUCKDB_API IndexKey(data_ptr_t data, idx_t len);
	DUCKDB_API IndexKey(ArenaAllocator &allocator, idx_t len);

	idx_t len = 0;
	data_ptr_t data;

public:
	virtual unique_ptr<IndexKey> CreateKey(ArenaAllocator &allocator, PhysicalType type, Value &value);

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

	inline bool ByteMatches(const unique_ptr<IndexKey> &other, idx_t depth) const {
		return data[depth] == (*other)[depth];
	}
	inline bool Empty() const {
		return len == 0;
	}

	virtual void Concat(ArenaAllocator &allocator, const unique_ptr<IndexKey> &other);
	virtual idx_t GetMismatchPos(const unique_ptr<IndexKey> &other, const idx_t start) const;
	virtual void VerifyKeyLength(const idx_t max_len) const;

	virtual row_t GetRowId() const;
};

} // namespace duckdb

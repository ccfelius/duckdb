//===----------------------------------------------------------------------===//
//                         DuckDB
//
// duckdb/execution/index/art/art_key.hpp
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
#include "duckdb/execution/index/index_key.hpp"

namespace duckdb {

class ARTKey : public IndexKey {
public:
	ARTKey();
	ARTKey(data_ptr_t data, idx_t len);
	ARTKey(ArenaAllocator &allocator, idx_t len);

public:
	template <class T>
	static inline unique_ptr<IndexKey> CreateARTKey(ArenaAllocator &allocator, T value) {
		auto data = ARTKey::CreateData<T>(allocator, value);
		return make_uniq<ARTKey>(data, sizeof(value));
	}

	template <class T>
	static inline unique_ptr<IndexKey> CreateARTKey(ArenaAllocator &allocator, Value &value) {
		return CreateARTKey(allocator, value.GetValueUnsafe<T>());
	}

	template <class T>
	static inline void CreateARTKey(ArenaAllocator &allocator, unique_ptr<IndexKey> &key, T value) {
		if (!key) {
			key = make_uniq<ARTKey>();
		}
		key->data = ARTKey::CreateData<T>(allocator, value);
		key->len = sizeof(value);
	}

	template <class T>
	static inline void CreateARTKey(ArenaAllocator &allocator, unique_ptr<IndexKey> &key, Value value) {
		if (!key) {
			key = make_uniq<ARTKey>();
		}
		key->data = ARTKey::CreateData<T>(allocator, value.GetValueUnsafe<T>());
		key->len = sizeof(value);
	}

	unique_ptr<IndexKey> CreateKey(ArenaAllocator &allocator, PhysicalType type, Value &value) override;
	static unique_ptr<IndexKey> CreateKeyStatic(ArenaAllocator &allocator, PhysicalType type, Value &value);

public:
	data_t &operator[](idx_t i) {
		return data[i];
	}
	const data_t &operator[](idx_t i) const {
		return data[i];
	}
	bool operator>(const ARTKey &key) const;
	bool operator>=(const ARTKey &key) const;
	bool operator==(const ARTKey &key) const;

	inline bool ByteMatches(const ARTKey &other, idx_t depth) const {
		return data[depth] == other[depth];
	}
	inline bool Empty() const {
		return len == 0;
	}

	void Concat(ArenaAllocator &allocator, const unique_ptr<IndexKey> &other) override;
	idx_t GetMismatchPos(const unique_ptr<IndexKey> &other, const idx_t start) const override;
	row_t GetRowId() const override;
	void VerifyKeyLength(const idx_t max_len) const override;

private:
	template <class T>
	static inline data_ptr_t CreateData(ArenaAllocator &allocator, T value) {
		auto data = allocator.Allocate(sizeof(value));
		Radix::EncodeData<T>(data, value);
		return data;
	}
};

template <>
unique_ptr<IndexKey> ARTKey::CreateARTKey(ArenaAllocator &allocator, string_t value);
template <>
unique_ptr<IndexKey> ARTKey::CreateARTKey(ArenaAllocator &allocator, const char *value);
template <>
void ARTKey::CreateARTKey(ArenaAllocator &allocator, unique_ptr<IndexKey> &key, string_t value);

} // namespace duckdb

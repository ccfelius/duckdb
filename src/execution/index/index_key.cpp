#include "duckdb/execution/index/index_key.hpp"

namespace duckdb {

//===--------------------------------------------------------------------===//
// IndexKey
//===--------------------------------------------------------------------===//

IndexKey::IndexKey() : len(0) {
}

IndexKey::IndexKey(const data_ptr_t data, idx_t len) : len(len), data(data) {
}

IndexKey::IndexKey(ArenaAllocator &allocator, idx_t len) : len(len) {
	data = allocator.Allocate(len);
}

void IndexKey::VerifyKeyLength(const idx_t max_len) const {
	if (len > max_len) {
		throw InvalidInputException("key size of %d bytes exceeds the maximum size of %d bytes for this ART", len,
		                            max_len);
	}
}

bool IndexKey::operator>(const IndexKey &key) const {
	for (idx_t i = 0; i < MinValue(len, key.len); i++) {
		if (data[i] > key.data[i]) {
			return true;
		} else if (data[i] < key.data[i]) {
			return false;
		}
	}
	return len > key.len;
}

bool IndexKey::operator>=(const IndexKey &key) const {
	for (idx_t i = 0; i < MinValue(len, key.len); i++) {
		if (data[i] > key.data[i]) {
			return true;
		} else if (data[i] < key.data[i]) {
			return false;
		}
	}
	return len >= key.len;
}

bool IndexKey::operator==(const IndexKey &key) const {
	if (len != key.len) {
		return false;
	}
	for (idx_t i = 0; i < len; i++) {
		if (data[i] != key.data[i]) {
			return false;
		}
	}
	return true;
}

void IndexKey::Concat(ArenaAllocator &allocator, const IndexKey &other) {
	auto compound_data = allocator.Allocate(len + other.len);
	memcpy(compound_data, data, len);
	memcpy(compound_data + len, other.data, other.len);
	len += other.len;
	data = compound_data;
}

row_t IndexKey::GetRowId() const {
	D_ASSERT(len == sizeof(row_t));
	return Radix::DecodeData<row_t>(data);
}

idx_t IndexKey::GetMismatchPos(const IndexKey &other, const idx_t start) const {
	D_ASSERT(len <= other.len);
	D_ASSERT(start <= len);
	for (idx_t i = start; i < other.len; i++) {
		if (data[i] != other.data[i]) {
			return i;
		}
	}
	return DConstants::INVALID_INDEX;
}

} // namespace duckdb

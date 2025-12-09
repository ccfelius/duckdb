#include "duckdb/execution/index/index_key.hpp"

namespace duckdb {

//===--------------------------------------------------------------------===//
// IndexKey
//===--------------------------------------------------------------------===//

IndexKey::IndexKey(const data_ptr_t data, idx_t len) : len(len), data(data) {
}

IndexKey::IndexKey(ArenaAllocator &allocator, idx_t len) : len(len) {
	data = allocator.Allocate(len);
}

unique_ptr<IndexKey> IndexKey::CreateKey(ArenaAllocator &allocator, PhysicalType type, Value &value) {
	throw NotImplementedException("IndexKey Abstract Class is called");
}

void IndexKey::VerifyKeyLength(const idx_t max_len) const {
	throw NotImplementedException("IndexKey Abstract Class is called");
}

data_t &IndexKey::operator[](idx_t i) {
	throw NotImplementedException("IndexKey Abstract Class is called");
}

const data_t &IndexKey::operator[](idx_t i) const {
	throw NotImplementedException("IndexKey Abstract Class is called");
}

bool IndexKey::operator>(const IndexKey &key) const {
	throw NotImplementedException("IndexKey Abstract Class is called");
}

bool IndexKey::operator>=(const IndexKey &key) const {
	throw NotImplementedException("IndexKey Abstract Class is called");
}

bool IndexKey::operator==(const IndexKey &key) const {
	throw NotImplementedException("IndexKey Abstract Class is called");
}

void IndexKey::Concat(ArenaAllocator &allocator, const unique_ptr<IndexKey> &other) {
	throw NotImplementedException("IndexKey Abstract Class is called");
}

idx_t IndexKey::GetMismatchPos(const unique_ptr<IndexKey> &other, const idx_t start) const {
	throw NotImplementedException("IndexKey Abstract Class is called");
}

row_t IndexKey::GetRowId() const {
	throw NotImplementedException("IndexKey Abstract Class is called");
}

} // namespace duckdb

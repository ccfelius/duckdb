#include "duckdb/storage/block.hpp"

#include "duckdb/common/assert.hpp"

namespace duckdb {

//! Add the  block header size here too!
Block::Block(Allocator &allocator, const block_id_t id, const idx_t block_size, const uint64_t block_header_size)
    : FileBuffer(allocator, FileBufferType::BLOCK, block_size, block_header_size), id(id) {
}

Block::Block(Allocator &allocator, block_id_t id, uint32_t internal_size, const uint64_t block_header_size)
    : FileBuffer(allocator, FileBufferType::BLOCK, internal_size, block_header_size), id(id) {
	D_ASSERT((AllocSize() & (Storage::SECTOR_SIZE - 1)) == 0);
}

Block::Block(FileBuffer &source, block_id_t id, const uint64_t block_header_size)
    : FileBuffer(source, FileBufferType::BLOCK), id(id) {
	D_ASSERT((AllocSize() & (Storage::SECTOR_SIZE - 1)) == 0);
}

} // namespace duckdb

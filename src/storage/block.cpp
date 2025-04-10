#include "duckdb/storage/block.hpp"

#include "duckdb/common/assert.hpp"

namespace duckdb {

//! TODO: also make sure the block_header_size is passed here
Block::Block(Allocator &allocator, const block_id_t id, const idx_t block_size, uint64_t block_header_size)
    : FileBuffer(allocator, FileBufferType::BLOCK, block_size, block_header_size), id(id) {
}

Block::Block(Allocator &allocator, block_id_t id, uint32_t internal_size, uint64_t block_header_size)
    : FileBuffer(allocator, FileBufferType::BLOCK, internal_size, block_header_size), id(id) {
	D_ASSERT((AllocSize() & (Storage::SECTOR_SIZE - 1)) == 0);
}

Block::Block(FileBuffer &source, block_id_t id, uint64_t block_header_size)
    : FileBuffer(source, FileBufferType::BLOCK, block_header_size), id(id) {
	D_ASSERT((AllocSize() & (Storage::SECTOR_SIZE - 1)) == 0);
}

} // namespace duckdb

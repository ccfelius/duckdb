//===----------------------------------------------------------------------===//
//                         DuckDB
//
// duckdb/storage/buffer/encrypted_buffer.hpp
//
//
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb/common/common.hpp"
#include "duckdb/common/file_buffer.hpp"
#include "duckdb/common/encryption_functions.hpp"
#include "duckdb/storage/storage_info.hpp"

namespace duckdb {

class Serializer;
class Deserializer;

class EncryptedBuffer : public FileBuffer {
public:
	EncryptedBuffer(Allocator &allocator, const block_id_t id, const idx_t block_size, const idx_t block_header_size);
	EncryptedBuffer(Allocator &allocator, block_id_t id, uint32_t internal_size, idx_t block_header_size);
	EncryptedBuffer(Allocator &allocator, const block_id_t id, BlockManager &block_manager);
	EncryptedBuffer(FileBuffer &source, block_id_t id);

	block_id_t id;

public:
	EncryptionTypes::CipherType cipher;
};

} // namespace duckdb

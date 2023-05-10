#include "duckdb/storage/magic_bytes.hpp"
#include "duckdb/storage/storage_info.hpp"
#include "duckdb/common/file_system.hpp"

namespace duckdb {

DataFileType MagicBytes::CheckMagicBytes(FileSystem &fs, const string &path) {
	auto handle = fs.TryOpenFile(path, FileFlags::FILE_FLAGS_READ);
	if (!handle) {
		return DataFileType::FILE_DOES_NOT_EXIST;
	}

	constexpr const idx_t MAGIC_BYTES_READ_SIZE = 16;
	char buffer[MAGIC_BYTES_READ_SIZE];

	handle->Read(buffer, MAGIC_BYTES_READ_SIZE);
	if (memcmp(buffer, "SQLite format 3\0\0\0", 16) == 0) {
		return DataFileType::SQLITE_FILE;
	}
	if (memcmp(buffer, "PAR1", 4) == 0) {
		return DataFileType::PARQUET_FILE;
	}
	if (memcmp(buffer + MainHeader::MAGIC_BYTE_OFFSET, MainHeader::MAGIC_BYTES, MainHeader::MAGIC_BYTE_SIZE) == 0) {
		return DataFileType::DUCKDB_FILE;
	}
	return DataFileType::FILE_DOES_NOT_EXIST;
}

} // namespace duckdb

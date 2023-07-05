//===----------------------------------------------------------------------===//
//                         DuckDB
//
// duckdb/execution/operator/persistent/csv_scanner/csv_buffer_manager.hpp
//
//
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb/main/client_context.hpp"
#include "duckdb/execution/operator/persistent/csv_scanner/csv_file_handle.hpp"

namespace duckdb {
class CSVBuffer;

//! This class is used to manage the buffers
//! Buffers are cached when used for auto detection
//! Otherwise they are not cached and just returned
class CSVBufferManager {
public:
	CSVBufferManager(ClientContext &context, unique_ptr<CSVFileHandle> file_handle);
	//! Returns a buffer from a buffer id (starting from 0). If it's in the auto-detection then we cache new buffers
	//! Otherwise we remove them from the cache if they are already there, or just return them bypassing the cache.
	shared_ptr<CSVBuffer> GetBuffer(idx_t pos, bool auto_detection);
	//! unique_ptr to the file handle, gets stolen after sniffing
	unique_ptr<CSVFileHandle> file_handle;

private:
	//! Reads next buffer in reference to cached_buffers.front()
	bool ReadNextAndCacheIt();
	vector<shared_ptr<CSVBuffer>> cached_buffers;
	shared_ptr<CSVBuffer> last_buffer;
	idx_t global_csv_pos = 0;
	//! The size of the buffer, if the csv file has a smaller size than this, we will use that instead to malloc less
	idx_t buffer_size = CSV_BUFFER_SIZE;
	ClientContext &context;
};

class CSVBufferIterator {
public:
	explicit CSVBufferIterator(shared_ptr<CSVBufferManager> buffer_manager_p)
	    : buffer_manager(std::move(buffer_manager_p)) {};

	//! Returns the next char in the CSV File
	//! Returns \0 if there are no more chars
	char GetNextChar();
	//! Returns true if the iterator is finished
	bool Finished();

private:
	idx_t cur_pos = 0;
	idx_t cur_buffer_idx = 0;
	shared_ptr<CSVBufferManager> buffer_manager;
	shared_ptr<CSVBuffer> cur_buffer;
};
} // namespace duckdb

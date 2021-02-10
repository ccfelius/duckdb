//===----------------------------------------------------------------------===//
//                         DuckDB
//
// duckdb/storage/table/transient_segment.hpp
//
//
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb/storage/table/column_segment.hpp"
#include "duckdb/storage/block.hpp"
#include "duckdb/storage/uncompressed_segment.hpp"

namespace duckdb {
struct ColumnAppendState;
class DatabaseInstance;
class PersistentSegment;

class TransientSegment : public ColumnSegment {
public:
	TransientSegment(DatabaseInstance &db, const LogicalType &type, idx_t start);
	explicit TransientSegment(PersistentSegment &segment);

	//! The storage manager
	DatabaseInstance &db;
	//! The uncompressed segment holding the data
	unique_ptr<UncompressedSegment> data;

public:
	void InitializeScan(ColumnScanState &state) override;
	//! Scan one vector from this transient segment
	void Scan(Transaction &transaction, ColumnScanState &state, idx_t vector_index, Vector &result) override;
	//! Scan one vector of committed data from this transient segment
	void ScanCommitted(ColumnScanState &state, idx_t vector_index, Vector &result) override;
	//! Scan the next vector from the column and apply a selection vector to filter the data
	void FilterScan(Transaction &transaction, ColumnScanState &state, Vector &result, SelectionVector &sel,
	                idx_t &approved_tuple_count) override;
	//! Scan one vector from this transient segment, throwing an exception if there are any outstanding updates
	void IndexScan(ColumnScanState &state, Vector &result) override;
	//! Executes the filters directly in the table's data
	void Select(Transaction &transaction, ColumnScanState &state, Vector &result, SelectionVector &sel,
	            idx_t &approved_tuple_count, vector<TableFilter> &table_filter) override;
	//! Fetch the base table vector index that belongs to this row
	void Fetch(ColumnScanState &state, idx_t vector_index, Vector &result) override;
	//! Fetch a value of the specific row id and append it to the result
	void FetchRow(ColumnFetchState &state, Transaction &transaction, row_t row_id, Vector &result,
	              idx_t result_idx) override;

	//! Perform an update within the transient segment
	void Update(ColumnData &column_data, Transaction &transaction, Vector &updates, row_t *ids, idx_t count) override;

	//! Initialize an append of this transient segment
	void InitializeAppend(ColumnAppendState &state);
	//! Appends a (part of) vector to the transient segment, returns the amount of entries successfully appended
	idx_t Append(ColumnAppendState &state, Vector &data, idx_t offset, idx_t count);
	//! Revert an append made to this transient segment
	void RevertAppend(idx_t start_row);
};

} // namespace duckdb

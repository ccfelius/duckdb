//===----------------------------------------------------------------------===//
//                         DuckDB
//
// duckdb/execution/radix_partitioned_hashtable.hpp
//
//
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb/execution/operator/aggregate/grouped_aggregate_data.hpp"
#include "duckdb/parser/group_by_node.hpp"

namespace duckdb {
class Executor;
class Pipeline;
class Task;

class RadixPartitionedHashTable {
public:
	RadixPartitionedHashTable(GroupingSet &grouping_set, const GroupedAggregateData &op);

	GroupingSet &grouping_set;
	//! The indices specified in the groups_count that do not appear in the grouping_set
	unsafe_vector<idx_t> null_groups;
	const GroupedAggregateData &op;

	vector<LogicalType> group_types;

	//! The GROUPING values that belong to this hash table
	vector<Value> grouping_values;

public:
	//! Sink Interface
	unique_ptr<GlobalSinkState> GetGlobalSinkState(ClientContext &context) const;
	unique_ptr<LocalSinkState> GetLocalSinkState(ExecutionContext &context) const;

	void Sink(ExecutionContext &context, DataChunk &chunk, OperatorSinkInput &input, DataChunk &aggregate_input_chunk,
	          const unsafe_vector<idx_t> &filter) const;
	void Combine(ExecutionContext &context, GlobalSinkState &gstate, LocalSinkState &lstate) const;
	bool Finalize(ClientContext &context, GlobalSinkState &gstate) const;

	void ScheduleTasks(Executor &executor, const shared_ptr<Event> &event, GlobalSinkState &gstate,
	                   vector<shared_ptr<Task>> &tasks) const;

	//! Source interface
	idx_t Count(GlobalSinkState &sink) const;
	unique_ptr<GlobalSourceState> GetGlobalSourceState(ClientContext &context) const;
	unique_ptr<LocalSourceState> GetLocalSourceState(ExecutionContext &context) const;
	SourceResultType GetData(ExecutionContext &context, DataChunk &chunk, GlobalSinkState &sink,
	                         OperatorSourceInput &input) const;

	static void SetMultiScan(GlobalSinkState &sink);

private:
	idx_t CountInternal(GlobalSinkState &sink) const;
	void SetGroupingValues();
	void PopulateGroupChunk(DataChunk &group_chunk, DataChunk &input_chunk) const;

	void CombineInternal(ExecutionContext &context, GlobalSinkState &gstate, LocalSinkState &lstate) const;
	static bool RequiresRepartitioning(ClientContext &context, GlobalSinkState &gstate);
};

} // namespace duckdb

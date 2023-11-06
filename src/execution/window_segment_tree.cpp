#include "duckdb/execution/window_segment_tree.hpp"

#include "duckdb/common/algorithm.hpp"
#include "duckdb/common/helper.hpp"
#include "duckdb/common/vector_operations/vector_operations.hpp"
#include "duckdb/execution/merge_sort_tree.hpp"
#include "duckdb/planner/expression/bound_constant_expression.hpp"
#include "duckdb/execution/window_executor.hpp"

#include <utility>

namespace duckdb {

//===--------------------------------------------------------------------===//
// WindowAggregator
//===--------------------------------------------------------------------===//
WindowAggregatorState::WindowAggregatorState() : allocator(Allocator::DefaultAllocator()) {
}

WindowAggregator::WindowAggregator(AggregateObject aggr, const LogicalType &result_type_p,
                                   const WindowExcludeMode exclude_mode_p, idx_t partition_count_p)
    : aggr(std::move(aggr)), result_type(result_type_p), partition_count(partition_count_p),
      state_size(aggr.function.state_size()), filter_pos(0), exclude_mode(exclude_mode_p) {
}

WindowAggregator::~WindowAggregator() {
}

void WindowAggregator::Sink(DataChunk &payload_chunk, SelectionVector *filter_sel, idx_t filtered) {
	if (!inputs.ColumnCount() && payload_chunk.ColumnCount()) {
		inputs.Initialize(Allocator::DefaultAllocator(), payload_chunk.GetTypes());
	}
	if (inputs.ColumnCount()) {
		inputs.Append(payload_chunk, true);
	}
	if (filter_sel) {
		//	Lazy instantiation
		if (!filter_mask.IsMaskSet()) {
			// 	Start with all invalid and set the ones that pass
			filter_bits.resize(ValidityMask::ValidityMaskSize(partition_count), 0);
			filter_mask.Initialize(filter_bits.data());
		}
		for (idx_t f = 0; f < filtered; ++f) {
			filter_mask.SetValid(filter_pos + filter_sel->get_index(f));
		}
		filter_pos += payload_chunk.size();
	}
}

void WindowAggregator::Finalize(const FrameStats &stats) {
}

//===--------------------------------------------------------------------===//
// WindowConstantAggregate
//===--------------------------------------------------------------------===//
WindowConstantAggregator::WindowConstantAggregator(AggregateObject aggr, const LogicalType &result_type,
                                                   const ValidityMask &partition_mask,
                                                   const WindowExcludeMode exclude_mode_p, const idx_t count)
    : WindowAggregator(std::move(aggr), result_type, exclude_mode_p, count), partition(0), row(0), state(state_size),
      statep(Value::POINTER(CastPointerToValue(state.data()))),
      statef(Value::POINTER(CastPointerToValue(state.data()))) {

	statef.SetVectorType(VectorType::FLAT_VECTOR); // Prevent conversion of results to constants

	// Locate the partition boundaries
	if (partition_mask.AllValid()) {
		partition_offsets.emplace_back(0);
	} else {
		idx_t entry_idx;
		idx_t shift;
		for (idx_t start = 0; start < count;) {
			partition_mask.GetEntryIndex(start, entry_idx, shift);

			//	If start is aligned with the start of a block,
			//	and the block is blank, then skip forward one block.
			const auto block = partition_mask.GetValidityEntry(entry_idx);
			if (partition_mask.NoneValid(block) && !shift) {
				start += ValidityMask::BITS_PER_VALUE;
				continue;
			}

			// Loop over the block
			for (; shift < ValidityMask::BITS_PER_VALUE && start < count; ++shift, ++start) {
				if (partition_mask.RowIsValid(block, shift)) {
					partition_offsets.emplace_back(start);
				}
			}
		}
	}

	//	Initialise the vector for caching the results
	results = make_uniq<Vector>(result_type, partition_offsets.size());
	partition_offsets.emplace_back(count);

	//	Create an aggregate state for intermediate aggregates
	gstate = make_uniq<WindowAggregatorState>();

	//	Start the first aggregate
	AggregateInit();
}

void WindowConstantAggregator::AggregateInit() {
	aggr.function.initialize(state.data());
}

void WindowConstantAggregator::AggegateFinal(Vector &result, idx_t rid) {
	AggregateInputData aggr_input_data(aggr.GetFunctionData(), gstate->allocator);
	aggr.function.finalize(statef, aggr_input_data, result, 1, rid);

	if (aggr.function.destructor) {
		aggr.function.destructor(statef, aggr_input_data, 1);
	}
}

void WindowConstantAggregator::Sink(DataChunk &payload_chunk, SelectionVector *filter_sel, idx_t filtered) {
	const auto chunk_begin = row;
	const auto chunk_end = chunk_begin + payload_chunk.size();

	if (!inputs.ColumnCount() && payload_chunk.ColumnCount()) {
		inputs.Initialize(Allocator::DefaultAllocator(), payload_chunk.GetTypes());
	}

	AggregateInputData aggr_input_data(aggr.GetFunctionData(), gstate->allocator);
	idx_t begin = 0;
	idx_t filter_idx = 0;
	auto partition_end = partition_offsets[partition + 1];
	while (row < chunk_end) {
		if (row == partition_end) {
			AggegateFinal(*results, partition++);
			AggregateInit();
			partition_end = partition_offsets[partition + 1];
		}
		partition_end = MinValue(partition_end, chunk_end);
		auto end = partition_end - chunk_begin;

		inputs.Reset();
		if (filter_sel) {
			// 	Slice to any filtered rows in [begin, end)
			SelectionVector sel;

			//	Find the first value in [begin, end)
			for (; filter_idx < filtered; ++filter_idx) {
				auto idx = filter_sel->get_index(filter_idx);
				if (idx >= begin) {
					break;
				}
			}

			//	Find the first value in [end, filtered)
			sel.Initialize(filter_sel->data() + filter_idx);
			idx_t nsel = 0;
			for (; filter_idx < filtered; ++filter_idx, ++nsel) {
				auto idx = filter_sel->get_index(filter_idx);
				if (idx >= end) {
					break;
				}
			}

			if (nsel != inputs.size()) {
				inputs.Slice(payload_chunk, sel, nsel);
			}
		} else {
			//	Slice to [begin, end)
			if (begin) {
				for (idx_t c = 0; c < payload_chunk.ColumnCount(); ++c) {
					inputs.data[c].Slice(payload_chunk.data[c], begin, end);
				}
			} else {
				inputs.Reference(payload_chunk);
			}
			inputs.SetCardinality(end - begin);
		}

		//	Aggregate the filtered rows into a single state
		const auto count = inputs.size();
		if (aggr.function.simple_update) {
			aggr.function.simple_update(inputs.data.data(), aggr_input_data, inputs.ColumnCount(), state.data(), count);
		} else {
			aggr.function.update(inputs.data.data(), aggr_input_data, inputs.ColumnCount(), statep, count);
		}

		//	Skip filtered rows too!
		row += end - begin;
		begin = end;
	}
}

void WindowConstantAggregator::Finalize(const FrameStats &stats) {
	AggegateFinal(*results, partition++);
}

class WindowConstantAggregatorState : public WindowAggregatorState {
public:
	WindowConstantAggregatorState() : partition(0) {
		matches.Initialize();
	}
	~WindowConstantAggregatorState() override {
	}

public:
	//! The current result partition being read
	idx_t partition;
	//! Shared SV for evaluation
	SelectionVector matches;
};

unique_ptr<WindowAggregatorState> WindowConstantAggregator::GetLocalState() const {
	return make_uniq<WindowConstantAggregatorState>();
}

void WindowConstantAggregator::Evaluate(WindowAggregatorState &lstate, const DataChunk &bounds, Vector &target,
                                        idx_t count, idx_t row_idx) const {
	auto begins = FlatVector::GetData<const idx_t>(bounds.data[WINDOW_BEGIN]);
	//	Chunk up the constants and copy them one at a time
	auto &lcstate = lstate.Cast<WindowConstantAggregatorState>();
	idx_t matched = 0;
	idx_t target_offset = 0;
	for (idx_t i = 0; i < count; ++i) {
		const auto begin = begins[i];
		//	Find the partition containing [begin, end)
		while (partition_offsets[lcstate.partition + 1] <= begin) {
			//	Flush the previous partition's data
			if (matched) {
				VectorOperations::Copy(*results, target, lcstate.matches, matched, 0, target_offset);
				target_offset += matched;
				matched = 0;
			}
			++lcstate.partition;
		}

		lcstate.matches.set_index(matched++, lcstate.partition);
	}

	//	Flush the last partition
	if (matched) {
		VectorOperations::Copy(*results, target, lcstate.matches, matched, 0, target_offset);
	}
}

//===--------------------------------------------------------------------===//
// WindowCustomAggregator
//===--------------------------------------------------------------------===//
WindowCustomAggregator::WindowCustomAggregator(AggregateObject aggr, const LogicalType &result_type,
                                               const WindowExcludeMode exclude_mode_p, idx_t count)
    : WindowAggregator(std::move(aggr), result_type, exclude_mode_p, count) {
}

WindowCustomAggregator::~WindowCustomAggregator() {
}

class WindowCustomAggregatorState : public WindowAggregatorState {
public:
	WindowCustomAggregatorState(const AggregateObject &aggr, const WindowExcludeMode exclude_mode);
	~WindowCustomAggregatorState() override;

public:
	//! The aggregate function
	const AggregateObject &aggr;
	//! Data pointer that contains a single state, shared by all the custom evaluators
	vector<data_t> state;
	//! Reused result state container for the window functions
	Vector statef;
	//! The frame boundaries, used for the window functions
	SubFrames frames;
};

WindowCustomAggregatorState::WindowCustomAggregatorState(const AggregateObject &aggr,
                                                         const WindowExcludeMode exclude_mode)
    : aggr(aggr), state(aggr.function.state_size()), statef(Value::POINTER(CastPointerToValue(state.data()))),
      frames(3, {0, 0}) {
	// if we have a frame-by-frame method, share the single state
	aggr.function.initialize(state.data());

	idx_t nframes = 0;
	switch (exclude_mode) {
	case WindowExcludeMode::NO_OTHER:
		nframes = 1;
		break;
	case WindowExcludeMode::TIES:
		nframes = 3;
		break;
	case WindowExcludeMode::CURRENT_ROW:
	case WindowExcludeMode::GROUP:
		nframes = 2;
		break;
	}
	frames.resize(nframes, {0, 0});
}

WindowCustomAggregatorState::~WindowCustomAggregatorState() {
	if (aggr.function.destructor) {
		AggregateInputData aggr_input_data(aggr.GetFunctionData(), allocator);
		aggr.function.destructor(statef, aggr_input_data, 1);
	}
}

void WindowCustomAggregator::Finalize(const FrameStats &stats) {
	WindowAggregator::Finalize(stats);
	partition_input =
	    make_uniq<WindowPartitionInput>(inputs.data.data(), inputs.ColumnCount(), inputs.size(), filter_mask, stats);

	if (aggr.function.window_init) {
		gstate = GetLocalState();
		auto &gcstate = gstate->Cast<WindowCustomAggregatorState>();

		AggregateInputData aggr_input_data(aggr.GetFunctionData(), gcstate.allocator);
		aggr.function.window_init(aggr_input_data, *partition_input, gcstate.state.data());
	}
}

unique_ptr<WindowAggregatorState> WindowCustomAggregator::GetLocalState() const {
	return make_uniq<WindowCustomAggregatorState>(aggr, exclude_mode);
}

void WindowCustomAggregator::Evaluate(WindowAggregatorState &lstate, const DataChunk &bounds, Vector &result,
                                      idx_t count, idx_t row_idx) const {
	auto begins = FlatVector::GetData<const idx_t>(bounds.data[WINDOW_BEGIN]);
	auto ends = FlatVector::GetData<const idx_t>(bounds.data[WINDOW_END]);
	auto peer_begin = FlatVector::GetData<const idx_t>(bounds.data[PEER_BEGIN]);
	auto peer_end = FlatVector::GetData<const idx_t>(bounds.data[PEER_END]);

	auto &lcstate = lstate.Cast<WindowCustomAggregatorState>();
	auto &frames = lcstate.frames;
	auto &rmask = FlatVector::Validity(result);
	const_data_ptr_t gstate_p = nullptr;
	if (gstate) {
		auto &gcstate = gstate->Cast<WindowCustomAggregatorState>();
		gstate_p = gcstate.state.data();
	}
	for (idx_t i = 0, cur_row = row_idx; i < count; ++i, ++cur_row) {
		idx_t nframes = 0;
		idx_t non_empty = 0;
		if (exclude_mode == WindowExcludeMode::NO_OTHER) {
			auto begin = begins[i];
			auto end = ends[i];
			non_empty += (begin < end);
			frames[nframes++] = FrameBounds(begin, end);
		} else {
			//	The frame_exclusion option allows rows around the current row to be excluded from the frame,
			//	even if they would be included according to the frame start and frame end options.
			//	EXCLUDE CURRENT ROW excludes the current row from the frame.
			//	EXCLUDE GROUP excludes the current row and its ordering peers from the frame.
			//	EXCLUDE TIES excludes any peers of the current row from the frame, but not the current row itself.
			//	EXCLUDE NO OTHERS simply specifies explicitly the default behavior
			//	of not excluding the current row or its peers.
			//	https://www.postgresql.org/docs/current/sql-expressions.html#SYNTAX-WINDOW-FUNCTIONS
			//
			//	For the sake of the client, we make some guarantees about the subframes:
			//	* They are in order left-to-right
			//	* They do not intersect
			//	* start <= end
			//	* The number is always the same
			//
			//	Since we always have peer_begin <= cur_row < cur_row + 1 <= peer_end
			//	this is not too hard to arrange, but it may be that some subframes are contiguous,
			//	and some are empty.

			//	WindowExcludePart::LEFT
			auto begin = begins[i];
			auto end = (exclude_mode == WindowExcludeMode::CURRENT_ROW) ? cur_row : peer_begin[i];
			end = MaxValue(begin, end);
			non_empty += (begin < end);
			frames[nframes++] = FrameBounds(begin, end);

			// with EXCLUDE TIES, in addition to the frame part right of the peer group's end,
			// we also need to consider the current row
			if (exclude_mode == WindowExcludeMode::TIES) {
				++non_empty;
				frames[nframes++] = FrameBounds(cur_row, cur_row + 1);
			}

			//	WindowExcludePart::RIGHT
			end = ends[i];
			begin = (exclude_mode == WindowExcludeMode::CURRENT_ROW) ? (cur_row + 1) : peer_end[i];
			begin = MinValue(begin, end);
			non_empty += (begin < end);
			frames[nframes++] = FrameBounds(begin, end);
		}

		//	No data means NULL
		if (!non_empty) {
			rmask.SetInvalid(i);
			continue;
		}

		// Extract the range
		AggregateInputData aggr_input_data(aggr.GetFunctionData(), lstate.allocator);
		aggr.function.window(aggr_input_data, *partition_input, gstate_p, lcstate.state.data(), frames, result, i);
	}
}

//===--------------------------------------------------------------------===//
// WindowExcludePart
//===--------------------------------------------------------------------===//
class WindowExcludePart {
public:
	enum FramePart : uint8_t { FULL = 0, LEFT = 1, RIGHT = 2 };

	WindowExcludePart(ArenaAllocator &allocator, const AggregateObject &aggr, DataChunk &inputs);
	virtual ~WindowExcludePart();

	template <class TARGET>
	TARGET &Cast() {
		D_ASSERT(dynamic_cast<TARGET *>(this));
		return reinterpret_cast<TARGET &>(*this);
	}
	template <class TARGET>
	const TARGET &Cast() const {
		D_ASSERT(dynamic_cast<const TARGET *>(this));
		return reinterpret_cast<const TARGET &>(*this);
	}

	virtual unique_ptr<WindowExcludePart> Copy() const = 0;
	virtual void Evaluate(const idx_t *begins, const idx_t *ends, Vector &result, idx_t count, idx_t row_idx,
	                      FramePart frame_part) = 0;
	virtual void Combine(WindowExcludePart &other, idx_t count);
	virtual void Finalize(Vector &result, idx_t count);

public:
	//! Allocator for aggregates
	ArenaAllocator &allocator;
	//! The aggregate function
	const AggregateObject &aggr;
	//! The aggregate function
	DataChunk &inputs;
	//! The size of a single aggregate state
	const idx_t state_size;
	//! Data pointer that contains a single state, used for intermediate window segment aggregation
	vector<data_t> state;
	//! Reused result state container for the window functions
	Vector statef;
};

WindowExcludePart::WindowExcludePart(ArenaAllocator &allocator, const AggregateObject &aggr, DataChunk &inputs)
    : allocator(allocator), aggr(aggr), inputs(inputs), state_size(aggr.function.state_size()),
      state(state_size * STANDARD_VECTOR_SIZE), statef(LogicalType::POINTER) {

	//	Build the finalise vector that just points to the result states
	data_ptr_t state_ptr = state.data();
	D_ASSERT(statef.GetVectorType() == VectorType::FLAT_VECTOR);
	statef.SetVectorType(VectorType::CONSTANT_VECTOR);
	statef.Flatten(STANDARD_VECTOR_SIZE);
	auto fdata = FlatVector::GetData<data_ptr_t>(statef);
	for (idx_t i = 0; i < STANDARD_VECTOR_SIZE; ++i) {
		fdata[i] = state_ptr;
		state_ptr += state_size;
	}
}

WindowExcludePart::~WindowExcludePart() {
}

void WindowExcludePart::Combine(WindowExcludePart &other, idx_t count) {
	AggregateInputData aggr_input_data(aggr.GetFunctionData(), allocator);
	aggr.function.combine(other.statef, statef, aggr_input_data, count);
}

void WindowExcludePart::Finalize(Vector &result, idx_t count) {
	//	Finalise the result aggregates and write to result if write_result is set
	AggregateInputData aggr_input_data(aggr.GetFunctionData(), allocator);
	aggr.function.finalize(statef, aggr_input_data, result, count, 0);

	//	Destruct the result aggregates
	if (aggr.function.destructor) {
		aggr.function.destructor(statef, aggr_input_data, count);
	}
}

//===--------------------------------------------------------------------===//
// WindowExcludeState
//===--------------------------------------------------------------------===//
class WindowExcludeState : public WindowAggregatorState {
public:
	WindowExcludeState(const AggregateObject &aggr, DataChunk &inputs, const WindowExcludeMode exclude_mode)
	    : aggr(aggr), inputs(inputs), exclude_mode(exclude_mode) {
	}

	virtual void Evaluate(const DataChunk &bounds, Vector &result, idx_t count, idx_t row_idx);

	//! The aggregate function
	const AggregateObject &aggr;
	//! The aggregate function
	DataChunk &inputs;
	//! The window exclusion clause
	const WindowExcludeMode exclude_mode;
	//! The left (default) distinct part
	unique_ptr<WindowExcludePart> part;
	//! The right distinct part (for EXCLUDE)
	unique_ptr<WindowExcludePart> right_part;
};

void WindowExcludeState::Evaluate(const DataChunk &bounds, Vector &result, idx_t count, idx_t row_idx) {

	auto window_begin = FlatVector::GetData<const idx_t>(bounds.data[WINDOW_BEGIN]);
	auto window_end = FlatVector::GetData<const idx_t>(bounds.data[WINDOW_END]);
	auto peer_begin = FlatVector::GetData<const idx_t>(bounds.data[PEER_BEGIN]);
	auto peer_end = FlatVector::GetData<const idx_t>(bounds.data[PEER_END]);

	if (exclude_mode != WindowExcludeMode::NO_OTHER) {
		// 1. evaluate the tree left of the excluded part
		part->Evaluate(window_begin, peer_begin, result, count, row_idx, WindowExcludePart::LEFT);

		// 2. set up a second state for the right of the excluded part
		if (!right_part) {
			right_part = part->Copy();
		}

		// 3. evaluate the tree right of the excluded part
		right_part->Evaluate(peer_end, window_end, result, count, row_idx, WindowExcludePart::RIGHT);

		// 4. combine the buffer state into the Segment Tree State
		part->Combine(*right_part, count);
	} else {
		part->Evaluate(window_begin, window_end, result, count, row_idx, WindowExcludePart::FULL);
	}

	part->Finalize(result, count);

	//	Set the validity mask on the invalid rows

	auto &rmask = FlatVector::Validity(result);
	for (idx_t rid = 0, cur_row = row_idx; rid < count; ++rid, ++cur_row) {
		auto begin = window_begin[rid];
		auto end = window_end[rid];
		if (begin >= end) {
			rmask.SetInvalid(rid);
		}
	}
}

//===--------------------------------------------------------------------===//
// WindowSegmentTree
//===--------------------------------------------------------------------===//
WindowSegmentTree::WindowSegmentTree(AggregateObject aggr, const LogicalType &result_type, WindowAggregationMode mode_p,
                                     const WindowExcludeMode exclude_mode_p, idx_t count)
    : WindowAggregator(std::move(aggr), result_type, exclude_mode_p, count), internal_nodes(0), mode(mode_p) {
}

void WindowSegmentTree::Finalize(const FrameStats &stats) {
	WindowAggregator::Finalize(stats);

	gstate = GetLocalState();
	if (inputs.ColumnCount() > 0) {
		if (aggr.function.combine && UseCombineAPI()) {
			ConstructTree();
		}
	}
}

WindowSegmentTree::~WindowSegmentTree() {
	if (!aggr.function.destructor) {
		// nothing to destroy
		return;
	}
	AggregateInputData aggr_input_data(aggr.GetFunctionData(), gstate->allocator);
	// call the destructor for all the intermediate states
	data_ptr_t address_data[STANDARD_VECTOR_SIZE];
	Vector addresses(LogicalType::POINTER, data_ptr_cast(address_data));
	idx_t count = 0;
	for (idx_t i = 0; i < internal_nodes; i++) {
		address_data[count++] = data_ptr_t(levels_flat_native.get() + i * state_size);
		if (count == STANDARD_VECTOR_SIZE) {
			aggr.function.destructor(addresses, aggr_input_data, count);
			count = 0;
		}
	}
	if (count > 0) {
		aggr.function.destructor(addresses, aggr_input_data, count);
	}
}

class WindowSegmentTreePart : public WindowExcludePart {
public:
	WindowSegmentTreePart(ArenaAllocator &allocator, const AggregateObject &aggr, DataChunk &inputs,
	                      const WindowSegmentTree &tree, const ValidityMask &filter_mask);
	~WindowSegmentTreePart() override;

	unique_ptr<WindowExcludePart> Copy() const override {
		return make_uniq<WindowSegmentTreePart>(allocator, aggr, inputs, tree, filter_mask);
	}

	void FlushStates(bool combining);
	void ExtractFrame(idx_t begin, idx_t end, data_ptr_t current_state);
	void WindowSegmentValue(idx_t l_idx, idx_t begin, idx_t end, data_ptr_t current_state);

	void Evaluate(const idx_t *begins, const idx_t *ends, Vector &result, idx_t count, idx_t row_idx,
	              FramePart frame_part) override;

public:
	//! The segment tree data
	const WindowSegmentTree &tree;
	//! The filtered rows in inputs
	const ValidityMask &filter_mask;
	//! Input data chunk, used for leaf segment aggregation
	DataChunk leaves;
	//! The filtered rows in inputs.
	SelectionVector filter_sel;
	//! A vector of pointers to "state", used for intermediate window segment aggregation
	Vector statep;
	//! Reused state pointers for combining segment tree levels
	Vector statel;
	//! Count of buffered values
	idx_t flush_count;
};

WindowSegmentTreePart::WindowSegmentTreePart(ArenaAllocator &allocator, const AggregateObject &aggr, DataChunk &inputs,
                                             const WindowSegmentTree &tree, const ValidityMask &filter_mask)
    : WindowExcludePart(allocator, aggr, inputs), tree(tree), filter_mask(filter_mask), statep(LogicalType::POINTER),
      statel(LogicalType::POINTER), flush_count(0) {
	if (inputs.ColumnCount() > 0) {
		leaves.Initialize(Allocator::DefaultAllocator(), inputs.GetTypes());
		filter_sel.Initialize();
	}
}

WindowSegmentTreePart::~WindowSegmentTreePart() {
}

class WindowSegmentTreeState : public WindowExcludeState {
public:
	WindowSegmentTreeState(const AggregateObject &aggr, DataChunk &inputs, const WindowExcludeMode exclude_mode,
	                       const WindowSegmentTree &tree, const ValidityMask &filter_mask)
	    : WindowExcludeState(aggr, inputs, exclude_mode) {

		part = make_uniq<WindowSegmentTreePart>(allocator, aggr, inputs, tree, filter_mask);
	}
};

unique_ptr<WindowAggregatorState> WindowSegmentTree::GetLocalState() const {
	return make_uniq<WindowSegmentTreeState>(aggr, const_cast<DataChunk &>(inputs), exclude_mode, *this, filter_mask);
}

void WindowSegmentTreePart::FlushStates(bool combining) {
	if (!flush_count) {
		return;
	}

	AggregateInputData aggr_input_data(aggr.GetFunctionData(), allocator);
	if (combining) {
		statel.Verify(flush_count);
		aggr.function.combine(statel, statep, aggr_input_data, flush_count);
	} else {
		leaves.Reference(inputs);
		leaves.Slice(filter_sel, flush_count);
		aggr.function.update(&leaves.data[0], aggr_input_data, leaves.ColumnCount(), statep, flush_count);
	}

	flush_count = 0;
}

void WindowSegmentTreePart::ExtractFrame(idx_t begin, idx_t end, data_ptr_t state_ptr) {
	const auto count = end - begin;

	//	If we are not filtering,
	//	just update the shared dictionary selection to the range
	//	Otherwise set it to the input rows that pass the filter
	auto states = FlatVector::GetData<data_ptr_t>(statep);
	if (filter_mask.AllValid()) {
		for (idx_t i = 0; i < count; ++i) {
			states[flush_count] = state_ptr;
			filter_sel.set_index(flush_count++, begin + i);
			if (flush_count >= STANDARD_VECTOR_SIZE) {
				FlushStates(false);
			}
		}
	} else {
		for (idx_t i = begin; i < end; ++i) {
			if (filter_mask.RowIsValid(i)) {
				states[flush_count] = state_ptr;
				filter_sel.set_index(flush_count++, i);
				if (flush_count >= STANDARD_VECTOR_SIZE) {
					FlushStates(false);
				}
			}
		}
	}
}

void WindowSegmentTreePart::WindowSegmentValue(idx_t l_idx, idx_t begin, idx_t end, data_ptr_t state_ptr) {
	D_ASSERT(begin <= end);
	if (begin == end || inputs.ColumnCount() == 0) {
		return;
	}

	const auto count = end - begin;
	if (l_idx == 0) {
		ExtractFrame(begin, end, state_ptr);
	} else {
		// find out where the states begin
		auto begin_ptr = tree.levels_flat_native.get() + state_size * (begin + tree.levels_flat_start[l_idx - 1]);
		// set up a vector of pointers that point towards the set of states
		auto ldata = FlatVector::GetData<data_ptr_t>(statel);
		auto pdata = FlatVector::GetData<data_ptr_t>(statep);
		for (idx_t i = 0; i < count; i++) {
			pdata[flush_count] = state_ptr;
			ldata[flush_count++] = begin_ptr;
			begin_ptr += state_size;
			if (flush_count >= STANDARD_VECTOR_SIZE) {
				FlushStates(true);
			}
		}
	}
}
void WindowSegmentTree::ConstructTree() {
	D_ASSERT(inputs.ColumnCount() > 0);

	//	Use a temporary scan state to build the tree
	auto &gpart = gstate->Cast<WindowSegmentTreeState>().part->Cast<WindowSegmentTreePart>();

	// compute space required to store internal nodes of segment tree
	internal_nodes = 0;
	idx_t level_nodes = inputs.size();
	do {
		level_nodes = (level_nodes + (TREE_FANOUT - 1)) / TREE_FANOUT;
		internal_nodes += level_nodes;
	} while (level_nodes > 1);
	levels_flat_native = make_unsafe_uniq_array<data_t>(internal_nodes * state_size);
	levels_flat_start.push_back(0);

	idx_t levels_flat_offset = 0;
	idx_t level_current = 0;
	// level 0 is data itself
	idx_t level_size;
	// iterate over the levels of the segment tree
	while ((level_size =
	            (level_current == 0 ? inputs.size() : levels_flat_offset - levels_flat_start[level_current - 1])) > 1) {
		for (idx_t pos = 0; pos < level_size; pos += TREE_FANOUT) {
			// compute the aggregate for this entry in the segment tree
			data_ptr_t state_ptr = levels_flat_native.get() + (levels_flat_offset * state_size);
			aggr.function.initialize(state_ptr);
			gpart.WindowSegmentValue(level_current, pos, MinValue(level_size, pos + TREE_FANOUT), state_ptr);
			gpart.FlushStates(level_current > 0);

			levels_flat_offset++;
		}

		levels_flat_start.push_back(levels_flat_offset);
		level_current++;
	}

	// Corner case: single element in the window
	if (levels_flat_offset == 0) {
		aggr.function.initialize(levels_flat_native.get());
	}
}

void WindowSegmentTree::Evaluate(WindowAggregatorState &lstate, const DataChunk &bounds, Vector &result, idx_t count,
                                 idx_t row_idx) const {

	auto &ltstate = lstate.Cast<WindowSegmentTreeState>();
	ltstate.Evaluate(bounds, result, count, row_idx);
}

void WindowSegmentTreePart::Evaluate(const idx_t *begins, const idx_t *ends, Vector &result, idx_t count, idx_t row_idx,
                                     FramePart frame_part) {

	const auto cant_combine = (!aggr.function.combine || !tree.UseCombineAPI());
	auto fdata = FlatVector::GetData<data_ptr_t>(statef);

	const auto exclude_mode = tree.exclude_mode;
	const bool begin_on_curr_row = frame_part == FramePart::RIGHT && exclude_mode == WindowExcludeMode::CURRENT_ROW;
	const bool end_on_curr_row = frame_part == FramePart::LEFT && exclude_mode == WindowExcludeMode::CURRENT_ROW;
	// with EXCLUDE TIES, in addition to the frame part right of the peer group's end, we also need to consider the
	// current row
	const bool add_curr_row = frame_part == FramePart::RIGHT && exclude_mode == WindowExcludeMode::TIES;

	//	First pass: aggregate the segment tree nodes
	//	Share adjacent identical states
	//  We do this first because we want to share only tree aggregations
	idx_t prev_begin = 1;
	idx_t prev_end = 0;
	auto ldata = FlatVector::GetData<data_ptr_t>(statel);
	auto pdata = FlatVector::GetData<data_ptr_t>(statep);
	data_ptr_t prev_state = nullptr;
	for (idx_t rid = 0, cur_row = row_idx; rid < count; ++rid, ++cur_row) {
		auto state_ptr = fdata[rid];
		aggr.function.initialize(state_ptr);

		if (cant_combine) {
			// Make sure we initialise all states
			continue;
		}

		auto begin = begin_on_curr_row ? cur_row + 1 : begins[rid];
		auto end = end_on_curr_row ? cur_row : ends[rid];
		if (begin >= end) {
			continue;
		}

		//	Skip level 0
		idx_t l_idx = 0;
		for (; l_idx < tree.levels_flat_start.size() + 1; l_idx++) {
			idx_t parent_begin = begin / tree.TREE_FANOUT;
			idx_t parent_end = end / tree.TREE_FANOUT;
			if (prev_state && l_idx == 1 && begin == prev_begin && end == prev_end) {
				//	Just combine the previous top level result
				ldata[flush_count] = prev_state;
				pdata[flush_count] = state_ptr;
				if (++flush_count >= STANDARD_VECTOR_SIZE) {
					FlushStates(true);
				}
				break;
			}

			if (l_idx == 1) {
				prev_state = state_ptr;
				prev_begin = begin;
				prev_end = end;
			}

			if (parent_begin == parent_end) {
				if (l_idx) {
					WindowSegmentValue(l_idx, begin, end, state_ptr);
				}
				break;
			}
			idx_t group_begin = parent_begin * tree.TREE_FANOUT;
			if (begin != group_begin) {
				if (l_idx) {
					WindowSegmentValue(l_idx, begin, group_begin + tree.TREE_FANOUT, state_ptr);
				}
				parent_begin++;
			}
			idx_t group_end = parent_end * tree.TREE_FANOUT;
			if (end != group_end) {
				if (l_idx) {
					WindowSegmentValue(l_idx, group_end, end, state_ptr);
				}
			}
			begin = parent_begin;
			end = parent_end;
		}
	}
	FlushStates(true);

	//	Second pass: aggregate the ragged leaves
	//	(or everything if we can't combine)
	for (idx_t rid = 0, cur_row = row_idx; rid < count; ++rid, ++cur_row) {
		auto state_ptr = fdata[rid];

		const auto begin = begin_on_curr_row ? cur_row + 1 : begins[rid];
		const auto end = end_on_curr_row ? cur_row : ends[rid];
		if (add_curr_row) {
			WindowSegmentValue(0, cur_row, cur_row + 1, state_ptr);
		}
		if (begin >= end) {
			continue;
		}

		// Aggregate everything at once if we can't combine states
		idx_t parent_begin = begin / tree.TREE_FANOUT;
		idx_t parent_end = end / tree.TREE_FANOUT;
		if (parent_begin == parent_end || cant_combine) {
			WindowSegmentValue(0, begin, end, state_ptr);
			continue;
		}

		idx_t group_begin = parent_begin * tree.TREE_FANOUT;
		if (begin != group_begin) {
			WindowSegmentValue(0, begin, group_begin + tree.TREE_FANOUT, state_ptr);
			parent_begin++;
		}
		idx_t group_end = parent_end * tree.TREE_FANOUT;
		if (end != group_end) {
			WindowSegmentValue(0, group_end, end, state_ptr);
		}
	}
	FlushStates(false);
}

//===--------------------------------------------------------------------===//
// WindowDistinctAggregator
//===--------------------------------------------------------------------===//
WindowDistinctAggregator::WindowDistinctAggregator(AggregateObject aggr, const LogicalType &result_type,
                                                   const WindowExcludeMode exclude_mode_p, idx_t count,
                                                   BufferManager &buffer_manager)
    : WindowAggregator(std::move(aggr), result_type, exclude_mode_p, count), buffer_manager(buffer_manager),
      allocator(Allocator::DefaultAllocator()) {

	payload_types.emplace_back(LogicalType::UBIGINT);
	payload_chunk.Initialize(Allocator::DefaultAllocator(), payload_types);

	payload_chunk.data[0].Sequence(0, 1, 0);
}

WindowDistinctAggregator::~WindowDistinctAggregator() {
}

void WindowDistinctAggregator::Sink(DataChunk &arg_chunk, SelectionVector *filter_sel, idx_t filtered) {
	WindowAggregator::Sink(arg_chunk, filter_sel, filtered);

	//	We sort the arguments and use the partition index as a tie-breaker.
	if (!global_sort) {
		//	1:	functionComputePrevIdcs(𝑖𝑛)
		//	2:		sorted ← []
		vector<LogicalType> sort_types;
		for (const auto &col : arg_chunk.data) {
			sort_types.emplace_back(col.GetType());
		}

		for (const auto &type : payload_types) {
			sort_types.emplace_back(type);
		}

		vector<BoundOrderByNode> orders;
		for (const auto &type : sort_types) {
			auto expr = make_uniq<BoundConstantExpression>(Value(type));
			orders.emplace_back(BoundOrderByNode(OrderType::ASCENDING, OrderByNullType::NULLS_FIRST, std::move(expr)));
		}

		RowLayout payload_layout;
		payload_layout.Initialize(payload_types);

		global_sort = make_uniq<GlobalSortState>(buffer_manager, orders, payload_layout);
		local_sort.Initialize(*global_sort, global_sort->buffer_manager);

		sort_chunk.Initialize(Allocator::DefaultAllocator(), sort_types);
		sort_chunk.data.back().Reference(payload_chunk.data[0]);
	}

	//	3: 	for i ← 0 to in.size do
	//	4: 		sorted[i] ← (in[i], i)

	//	TODO: Filter out rows
	int64_t start, increment, sequence_count;
	SequenceVector::GetSequence(payload_chunk.data[0], start, increment, sequence_count);
	sequence_count = arg_chunk.size();

	for (column_t c = 0; c < arg_chunk.ColumnCount(); ++c) {
		sort_chunk.data[c].Reference(arg_chunk.data[c]);
	}

	local_sort.SinkChunk(sort_chunk, payload_chunk);

	// 	if (local_sort.SizeInBytes() > merge_state->memory_per_thread) {
	// 		local_sort.Sort(global_sort, true);
	// 	}

	start += sequence_count;
	sequence_count = 0;
}

class WindowDistinctAggregator::DistinctSortTree : public MergeSortTree<idx_t, idx_t> {
public:
	using BaseTree = MergeSortTree<idx_t, idx_t>;
	DistinctSortTree(Elements &&lowest_level, WindowDistinctAggregator &wda);

	//! The actual window segment tree: an array of aggregate states that represent all the intermediate nodes
	unsafe_unique_array<data_t> levels_flat_native;
	//! For each level, the starting location in the levels_flat_native array
	vector<idx_t> levels_flat_start;

	//! The total number of internal nodes of the tree, stored in levels_flat_native
	idx_t internal_nodes;
};

void WindowDistinctAggregator::Finalize(const FrameStats &stats) {
	//	5: Sort sorted lexicographically increasing
	global_sort->AddLocalState(local_sort);
	global_sort->PrepareMergePhase();
	while (global_sort->sorted_blocks.size() > 1) {
		global_sort->InitializeMergeRound();
		MergeSorter merge_sorter(*global_sort, global_sort->buffer_manager);
		merge_sorter.PerformInMergeRound();
		global_sort->CompleteMergeRound(false);
	}

	//	6:	prevIdcs ← []
	//	7:	prevIdcs[0] ← “-”
	const auto count = inputs.size();
	vector<idx_t> prev_idcs;
	prev_idcs.reserve(count);
	prev_idcs[0] = 0;

	DataChunk scan_chunk;
	scan_chunk.Initialize(Allocator::DefaultAllocator(), payload_types);

	auto scanner = make_uniq<PayloadScanner>(*global_sort);
	scanner->Scan(scan_chunk);
	idx_t scan_idx = 0;
	auto *second = FlatVector::GetData<idx_t>(scan_chunk.data[0]);

	SBIterator curr(*global_sort, ExpressionType::COMPARE_LESSTHAN);
	SBIterator prev(*global_sort, ExpressionType::COMPARE_LESSTHAN);
	const auto &sort_layout = global_sort->sort_layout;

	//	8:	for i ← 1 to in.size do
	for (++curr; curr.GetIndex() < count; ++curr, ++prev) {
		//	Scan second one chunk at a time
		//	Note the scan is one behind the iterators
		if (scan_idx >= scan_chunk.size()) {
			scan_chunk.Reset();
			scanner->Scan(scan_chunk);
			scan_idx = 0;
		}

		int lt = 0;
		if (sort_layout.all_constant) {
			lt = FastMemcmp(prev.entry_ptr, curr.entry_ptr, sort_layout.comparison_size);
		} else {
			lt = Comparators::CompareTuple(prev.scan, curr.scan, prev.entry_ptr, curr.entry_ptr, sort_layout,
			                               prev.external);
		}

		//	9:	if sorted[i].first == sorted[i-1].first then
		//	10:		prevIdcs[i] ← sorted[i-1].second
		//	11:	else
		//	12:		prevIdcs[i] ← “-”
		if (!lt) {
			prev_idcs.emplace_back(second[scan_idx] + 1);
		} else {
			prev_idcs.emplace_back(0);
		}
	}
	//	13:	return prevIdcs

	merge_sort_tree = make_uniq<DistinctSortTree>(std::move(prev_idcs), *this);
}

WindowDistinctAggregator::DistinctSortTree::DistinctSortTree(Elements &&lowest_level, WindowDistinctAggregator &wda)
    : BaseTree(std::move(lowest_level)) {

	auto &inputs = wda.inputs;
	auto &aggr = wda.aggr;
	auto &allocator = wda.allocator;
	const auto state_size = wda.state_size;

	//! Input data chunk, used for leaf segment aggregation
	DataChunk leaves;
	leaves.Initialize(Allocator::DefaultAllocator(), inputs.GetTypes());
	SelectionVector sel;
	sel.Initialize();

	AggregateInputData aggr_input_data(aggr.GetFunctionData(), allocator);

	//! The states to update
	Vector update_v(LogicalType::POINTER);
	auto updates = FlatVector::GetData<data_ptr_t>(update_v);
	idx_t nupdate = 0;

	Vector source_v(LogicalType::POINTER);
	auto sources = FlatVector::GetData<data_ptr_t>(source_v);
	Vector target_v(LogicalType::POINTER);
	auto targets = FlatVector::GetData<data_ptr_t>(target_v);
	idx_t ncombine = 0;

	// compute space required to store aggregation states of merge sort tree
	// this is one aggregate state per entry per level
	internal_nodes = 0;
	for (idx_t level_nr = 0; level_nr < tree.size(); ++level_nr) {
		internal_nodes += tree[level_nr].first.size();
	}
	levels_flat_native = make_unsafe_uniq_array<data_t>(internal_nodes * state_size);
	levels_flat_start.push_back(0);
	idx_t levels_flat_offset = 0;

	//	Walk the distinct value tree building the intermediate aggregates
	idx_t level_width = 1;
	for (idx_t level_nr = 0; level_nr < tree.size(); ++level_nr) {
		auto &level = tree[level_nr].first;

		for (idx_t i = 0; i < level.size(); i += level_width) {
			//	Reset the combine state
			data_ptr_t prev_state = nullptr;
			auto next_limit = MinValue<idx_t>(level.size(), i + level_width);
			for (auto j = i; j < next_limit; ++j) {
				//	Initialise the next aggregate
				auto curr_state = levels_flat_native.get() + (levels_flat_offset++ * state_size);
				aggr.function.initialize(curr_state);

				//	Update this state (if it matches)
				if (level[j] < i + 1) {
					updates[nupdate] = curr_state;
					sel[nupdate] = level[j];
					++nupdate;
				}

				//	Merge the previous state (if any)
				if (prev_state) {
					sources[ncombine] = prev_state;
					targets[ncombine] = curr_state;
					++ncombine;
				}
				prev_state = curr_state;

				//	Flush the states if one is maxed out.
				if (MaxValue<idx_t>(ncombine, nupdate) >= STANDARD_VECTOR_SIZE) {
					//	Push the updates first so they propagate
					leaves.Reference(inputs);
					leaves.Slice(sel, nupdate);
					aggr.function.update(leaves.data.data(), aggr_input_data, leaves.ColumnCount(), update_v, nupdate);
					nupdate = 0;

					//	Combine the states sequentially
					aggr.function.combine(source_v, target_v, aggr_input_data, ncombine);
					ncombine = 0;
				}
			}
		}

		levels_flat_start.push_back(levels_flat_offset);
		level_width *= FANOUT;
	}

	//	Flush any remaining states
	if (ncombine || nupdate) {
		//	Push  the updates
		leaves.Reference(inputs);
		leaves.Slice(sel, nupdate);
		aggr.function.update(leaves.data.data(), aggr_input_data, leaves.ColumnCount(), update_v, nupdate);
		nupdate = 0;

		//	Combine the states sequentially
		aggr.function.combine(source_v, target_v, aggr_input_data, ncombine);
		ncombine = 0;
	}
}

void WindowDistinctAggregator::Evaluate(WindowAggregatorState &lstate, const DataChunk &bounds, Vector &result,
                                        idx_t count, idx_t row_idx) const {
#if 0
	auto window_begin = FlatVector::GetData<const idx_t>(bounds.data[WINDOW_BEGIN]);
	auto window_end = FlatVector::GetData<const idx_t>(bounds.data[WINDOW_END]);
	auto peer_begin = FlatVector::GetData<const idx_t>(bounds.data[PEER_BEGIN]);
	auto peer_end = FlatVector::GetData<const idx_t>(bounds.data[PEER_END]);

	for (idx_t rid = 0, cur_row = row_idx; rid < count; ++rid, ++cur_row) {
		const auto lower = window_begin[rid];
		const auto upper = window_end[rid];

    	auto aggState = Agg::init();
    	merge_sort_tree->AggregateLowerBound(lower, upper, lower + 1,
    		[&](idx_t level, const idx_t begin, const idx_t pos) {
      			if (pos != begin) {
      				const auto idx = pos - merge_sort_tree.tree[level].first.data() - 1;
        			aggState = Agg::merge(aggState, runningAggs[level][idx]);
      			}
    		});
    	result.push_back(aggState);
  	}
#endif
}
} // namespace duckdb

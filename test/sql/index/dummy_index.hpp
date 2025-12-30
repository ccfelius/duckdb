#include "duckdb/execution/index/bound_index.hpp"
#include "duckdb/execution/index/art/node.hpp"
#include "duckdb/common/array.hpp"

using namespace duckdb;

namespace duckdb {

class DUMMY_INDEX : public BoundIndex {
public:
	friend class Leaf;

public:
	//! Index type name for the DUMMY.
	static constexpr const char *TYPE_NAME = "DUMMY";
	//! FixedSizeAllocator count of the DUMMY
	static constexpr uint8_t ALLOCATOR_COUNT = 9;
	//! Keys must not exceed MAX_KEY_LEN * prefix_count.
	static constexpr idx_t MAX_KEY_LEN = 8192;

public:
	DUMMY_INDEX(
	    const string &name, const IndexConstraintType index_constraint_type, const vector<column_t> &column_ids,
	    TableIOManager &table_io_manager, const vector<unique_ptr<Expression>> &unbound_expressions,
	    AttachedDatabase &db,
	    const shared_ptr<array<unsafe_unique_ptr<FixedSizeAllocator>, ALLOCATOR_COUNT>> &allocators_ptr = nullptr,
	    const IndexStorageInfo &info = IndexStorageInfo());

	~DUMMY_INDEX() override;

	//! Create an index instance of this type.
	static duckdb::unique_ptr<DUMMY_INDEX> Create(CreateIndexInput &input);
	static IndexType GetDummyIndexType();
};
} // namespace duckdb

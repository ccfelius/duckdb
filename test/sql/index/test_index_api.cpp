#include "catch.hpp"
#include "duckdb/common/radix.hpp"
#include "test_helpers.hpp"
#include "duckdb/execution/index/dummy_index.hpp"

#include <cfloat>
#include <iostream>
#include <duckdb/execution/index/dummy_index.hpp>

using namespace duckdb;
using namespace std;

void RegisterIndex(DatabaseInstance &db) {

	IndexType index_type;

	index_type.name = DUMMY_INDEX::TYPE_NAME;
}

TEST_CASE("Create new index type", "[index][api]") {
	duckdb::unique_ptr<QueryResult> result;
	DuckDB db(nullptr);
	Connection con(db);

	IndexType custom_index;

}


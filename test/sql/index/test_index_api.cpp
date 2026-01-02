#include "catch.hpp"
#include "duckdb/common/radix.hpp"
#include "test_helpers.hpp"
#include "dummy_index.hpp"

#include <cfloat>
#include <iostream>
#include <duckdb/execution/index/dummy_index.hpp>

using namespace duckdb;
using namespace std;

void RegisterIndex(DatabaseInstance &db) {

	IndexType index_type;

	index_type.name = DUMMY_INDEX::TYPE_NAME;
	index_type.build_bind = DUMMY_INDEX::BUILD_BIND;


	index_type.create_instance = [](CreateIndexInput &input) -> unique_ptr<BoundIndex> {
		auto res = make_uniq<HNSWIndex>(input.name, input.constraint_type, input.column_ids, input.table_io_manager,
										input.unbound_expressions, input.db, input.options, input.storage_info);
		return std::move(res);
	};
	index_type.create_plan = DUMMY_INDEX::CreatePlan;

	// Register persistence option
	db.config.AddExtensionOption("hnsw_enable_experimental_persistence",
								 "experimental: enable creating HNSW indexes in persistent databases",
								 LogicalType::BOOLEAN, Value::BOOLEAN(false));

	// Register scan option
	db.config.AddExtensionOption("hnsw_ef_search",
								 "experimental: override the ef_search parameter when scanning HNSW indexes",
								 LogicalType::BIGINT);

	// Register the index type
	db.config.GetIndexTypes().RegisterIndexType(index_type);
}

TEST_CASE("Create new index type", "[index][api]") {
	duckdb::unique_ptr<QueryResult> result;
	DuckDB db(nullptr);
	Connection con(db);

	IndexType custom_index;

}

// If you directly use RAND_MAX:
// > warning: implicit conversion from 'int' to 'float' changes value from 2147483647 to 2147483648in_float));
}

double generate_small_double() {
	return static_cast<double>(rand()) / static_cast<double>(RAND_MAX);
}

double generate_double(double min_double, double max_double) {
	return min_double + static_cast<double>(rand()) / (static_cast<double>(RAND_MAX / (max_double - min_double)));
}

template <class T>
int full_scan(T *keys, idx_t size, T low, T high) {
	int sum = 0;
	for (idx_t i = 0; i < size; i++) {
		if (keys[i] >= low && keys[i] <= high) {
			sum += 1;
		}
	}
	return sum;
}

TEST_CASE("DUMMY Floating Point Small", "[DUMMY-float-small]") {
	duckdb::unique_ptr<QueryResult> result;
	DuckDB db(nullptr);
	int64_t a, b;
	duckdb::vector<int64_t> min_values, max_values;
	Connection con(db);
	// Will use 100 keys
	idx_t n = 100;
	auto keys = duckdb::unique_ptr<int64_t[]>(new int64_t[n]);
	REQUIRE_NO_FAIL(con.Query("CREATE TABLE numbers(i BIGINT)"));
	// Generate 10 small floats (0.0 - 1.0)
	for (idx_t i = 0; i < n / 10; i++) {
		keys[i] = Radix::EncodeFloat(generate_small_float());
	}

	// Generate 40 floats (-50/50)
	for (idx_t i = n / 10; i < n / 2; i++) {
		keys[i] = Radix::EncodeFloat(generate_float(-50, 50));
	}
	// Generate 50 floats (min/max)
	for (idx_t i = n / 2; i < n; i++) {
		keys[i] = Radix::EncodeFloat(generate_float(FLT_MIN, FLT_MAX));
	}
	// Insert values and create index
	REQUIRE_NO_FAIL(con.Query("BEGIN TRANSACTION"));
	for (idx_t i = 0; i < n; i++) {
		REQUIRE_NO_FAIL(con.Query("INSERT INTO numbers VALUES (" + to_string(keys[i]) + ")"));
	}
	REQUIRE_NO_FAIL(con.Query("COMMIT"));
	REQUIRE_NO_FAIL(con.Query("CREATE INDEX i_index ON numbers(i)"));
	// Generate 500 small-small range queries
	for (idx_t i = 0; i < 5; i++) {
		a = Radix::EncodeFloat(generate_small_float());
		b = Radix::EncodeFloat(generate_small_float());
		min_values.push_back(min(a, b));
		max_values.push_back(max(a, b));
	}
	// Generate 500 normal-normal range queries
	for (idx_t i = 0; i < 5; i++) {
		a = Radix::EncodeFloat(generate_float(-50, 50));
		b = Radix::EncodeFloat(generate_float(-50, 50));
		min_values.push_back(min(a, b));
		max_values.push_back(max(a, b));
	}
	// Generate 500 big-big range queries
	for (idx_t i = 0; i < 5; i++) {
		a = Radix::EncodeFloat(generate_float(FLT_MIN, FLT_MAX));
		b = Radix::EncodeFloat(generate_float(FLT_MIN, FLT_MAX));
		min_values.push_back(min(a, b));
		max_values.push_back(max(a, b));
	}
	for (idx_t i = 0; i < min_values.size(); i++) {
		int64_t low = Radix::EncodeFloat(min_values[i]);
		int64_t high = Radix::EncodeFloat(max_values[i]);
		int answer = full_scan<int64_t>(keys.get(), n, low, high);
		string query =
		    "SELECT COUNT(i) FROM numbers WHERE i >= " + to_string(low) + " and i <= " + to_string(high) + ";";
		result = con.Query(query);
		if (!CHECK_COLUMN(result, 0, {answer})) {
			cout << "Wrong answer on floating point real-small!" << std::endl << "Queries to reproduce:" << std::endl;
			cout << "CREATE TABLE numbers(i BIGINT);" << std::endl;
			for (idx_t k = 0; k < n; k++) {
				cout << "INSERT INTO numbers VALUES (" << keys[k] << ");" << std::endl;
			}
			cout << query << std::endl;
			REQUIRE(false);
		}
	}
	REQUIRE_NO_FAIL(con.Query("DROP INDEX i_index"));
	REQUIRE_NO_FAIL(con.Query("DROP TABLE numbers"));
}

TEST_CASE("DUMMY Floating Point Double Small", "[DUMMY-double-small]") {
	duckdb::unique_ptr<QueryResult> result;
	DuckDB db(nullptr);
	int64_t a, b;
	duckdb::vector<int64_t> min_values, max_values;
	Connection con(db);
	// Will use 100 keys
	idx_t n = 100;
	auto keys = duckdb::unique_ptr<int64_t[]>(new int64_t[n]);
	REQUIRE_NO_FAIL(con.Query("CREATE TABLE numbers(i BIGINT)"));
	// Generate 10 small floats (0.0 - 1.0)
	for (idx_t i = 0; i < n / 10; i++) {
		keys[i] = Radix::EncodeFloat(generate_small_float());
	}

	// Generate 40 floats (-50/50)
	for (idx_t i = n / 10; i < n / 2; i++) {
		keys[i] = Radix::EncodeFloat(generate_float(-50, 50));
	}
	// Generate 50 floats (min/max)
	for (idx_t i = n / 2; i < n; i++) {
		keys[i] = Radix::EncodeFloat(generate_float(FLT_MIN, FLT_MAX));
	}
	// Insert values and create index
	REQUIRE_NO_FAIL(con.Query("BEGIN TRANSACTION"));
	for (idx_t i = 0; i < n; i++) {
		REQUIRE_NO_FAIL(con.Query("INSERT INTO numbers VALUES (" + to_string(keys[i]) + ")"));
	}
	REQUIRE_NO_FAIL(con.Query("COMMIT"));
	REQUIRE_NO_FAIL(con.Query("CREATE INDEX i_index ON numbers(i)"));
	// Generate 500 small-small range queries
	for (idx_t i = 0; i < 5; i++) {
		a = Radix::EncodeDouble(generate_small_double());
		b = Radix::EncodeDouble(generate_small_double());
		min_values.push_back(min(a, b));
		max_values.push_back(max(a, b));
	}
	// Generate 500 normal-normal range queries
	for (idx_t i = 0; i < 5; i++) {
		a = Radix::EncodeDouble(generate_double(-50, 50));
		b = Radix::EncodeDouble(generate_double(-50, 50));
		min_values.push_back(min(a, b));
		max_values.push_back(max(a, b));
	}
	// Generate 500 big-big range queries
	for (idx_t i = 0; i < 5; i++) {
		a = Radix::EncodeDouble(generate_double(FLT_MIN, FLT_MAX));
		b = Radix::EncodeDouble(generate_double(FLT_MIN, FLT_MAX));
		min_values.push_back(min(a, b));
		max_values.push_back(max(a, b));
	}
	for (idx_t i = 0; i < min_values.size(); i++) {
		int64_t low = Radix::EncodeDouble(min_values[i]);
		int64_t high = Radix::EncodeDouble(max_values[i]);
		int answer = full_scan<int64_t>(keys.get(), n, low, high);
		string query =
		    "SELECT COUNT(i) FROM numbers WHERE i >= " + to_string(low) + " and i <= " + to_string(high) + ";";
		result = con.Query(query);
		if (!CHECK_COLUMN(result, 0, {answer})) {
			cout << "Wrong answer on double!" << std::endl << "Queries to reproduce:" << std::endl;
			cout << "CREATE TABLE numbers(i BIGINT);" << std::endl;
			for (idx_t k = 0; k < n; k++) {
				cout << "INSERT INTO numbers VALUES (" << keys[k] << ");" << std::endl;
			}
			cout << query << std::endl;
			REQUIRE(false);
		}
	}
	REQUIRE_NO_FAIL(con.Query("DROP INDEX i_index"));
	REQUIRE_NO_FAIL(con.Query("DROP TABLE numbers"));
}

TEST_CASE("DUMMY Floating Point", "[DUMMY-float][.]") {
	duckdb::unique_ptr<QueryResult> result;
	DuckDB db(nullptr);
	int64_t a, b;
	duckdb::vector<int64_t> min_values, max_values;
	Connection con(db);
	// Will use 10k keys
	idx_t n = 10000;
	auto keys = duckdb::unique_ptr<int64_t[]>(new int64_t[n]);
	REQUIRE_NO_FAIL(con.Query("CREATE TABLE numbers(i BIGINT)"));
	// Generate 1000 small floats (0.0 - 1.0)
	for (idx_t i = 0; i < n / 10; i++) {
		keys[i] = Radix::EncodeFloat(generate_small_float());
	}

	// Generate 4000 floats (-50/50)
	for (idx_t i = n / 10; i < n / 2; i++) {
		keys[i] = Radix::EncodeFloat(generate_float(-50, 50));
	}
	// Generate 5000 floats (min/max)
	for (idx_t i = n / 2; i < n; i++) {
		keys[i] = Radix::EncodeFloat(generate_float(FLT_MIN, FLT_MAX));
	}
	// Insert values and create index
	REQUIRE_NO_FAIL(con.Query("BEGIN TRANSACTION"));
	for (idx_t i = 0; i < n; i++) {
		REQUIRE_NO_FAIL(con.Query("INSERT INTO numbers VALUES (" + to_string(keys[i]) + ")"));
	}
	REQUIRE_NO_FAIL(con.Query("COMMIT"));
	REQUIRE_NO_FAIL(con.Query("CREATE INDEX i_index ON numbers(i)"));
	// Generate 500 small-small range queries
	for (idx_t i = 0; i < 500; i++) {
		a = Radix::EncodeFloat(generate_small_float());
		b = Radix::EncodeFloat(generate_small_float());
		min_values.push_back(min(a, b));
		max_values.push_back(max(a, b));
	}
	// Generate 500 normal-normal range queries
	for (idx_t i = 0; i < 500; i++) {
		a = Radix::EncodeFloat(generate_float(-50, 50));
		b = Radix::EncodeFloat(generate_float(-50, 50));
		min_values.push_back(min(a, b));
		max_values.push_back(max(a, b));
	}
	// Generate 500 big-big range queries
	for (idx_t i = 0; i < 500; i++) {
		a = Radix::EncodeFloat(generate_float(FLT_MIN, FLT_MAX));
		b = Radix::EncodeFloat(generate_float(FLT_MIN, FLT_MAX));
		min_values.push_back(min(a, b));
		max_values.push_back(max(a, b));
	}
	for (idx_t i = 0; i < min_values.size(); i++) {
		int64_t low = Radix::EncodeFloat(min_values[i]);
		int64_t high = Radix::EncodeFloat(max_values[i]);
		int answer = full_scan<int64_t>(keys.get(), n, low, high);
		string query =
		    "SELECT COUNT(i) FROM numbers WHERE i >= " + to_string(low) + " and i <= " + to_string(high) + ";";
		result = con.Query(query);
		if (!CHECK_COLUMN(result, 0, {answer})) {
			cout << "Wrong answer on floating point real-small!" << std::endl << "Queries to reproduce:" << std::endl;
			cout << "CREATE TABLE numbers(i BIGINT);" << std::endl;
			for (idx_t k = 0; k < n; k++) {
				cout << "INSERT INTO numbers VALUES (" << keys[k] << ");" << std::endl;
			}
			cout << query << std::endl;
			REQUIRE(false);
		}
	}
	REQUIRE_NO_FAIL(con.Query("DROP INDEX i_index"));
	REQUIRE_NO_FAIL(con.Query("DROP TABLE numbers"));
}

TEST_CASE("DUMMY Floating Point Double", "[DUMMY-double][.]") {
	duckdb::unique_ptr<QueryResult> result;
	DuckDB db(nullptr);
	int64_t a, b;
	duckdb::vector<int64_t> min_values, max_values;
	Connection con(db);
	// Will use 10000 keys
	idx_t n = 10000;
	auto keys = duckdb::unique_ptr<int64_t[]>(new int64_t[n]);
	con.Query("CREATE TABLE numbers(i BIGINT)");
	// Generate 1000 small floats (0.0 - 1.0)
	for (idx_t i = 0; i < n / 10; i++) {
		keys[i] = Radix::EncodeFloat(generate_small_float());
	}

	// Generate 4000 floats (-50/50)
	for (idx_t i = n / 10; i < n / 2; i++) {
		keys[i] = Radix::EncodeFloat(generate_float(-50, 50));
	}
	// Generate 5000 floats (min/max)
	for (idx_t i = n / 2; i < n; i++) {
		keys[i] = Radix::EncodeFloat(generate_float(FLT_MIN, FLT_MAX));
	}
	// Insert values and create index
	REQUIRE_NO_FAIL(con.Query("BEGIN TRANSACTION"));
	for (idx_t i = 0; i < n; i++) {
		REQUIRE_NO_FAIL(con.Query("INSERT INTO numbers VALUES (" + to_string(keys[i]) + ")"));
	}
	REQUIRE_NO_FAIL(con.Query("COMMIT"));
	REQUIRE_NO_FAIL(con.Query("CREATE INDEX i_index ON numbers(i)"));
	// Generate 500 small-small range queries
	for (idx_t i = 0; i < 500; i++) {
		a = Radix::EncodeDouble(generate_small_double());
		b = Radix::EncodeDouble(generate_small_double());
		min_values.push_back(min(a, b));
		max_values.push_back(max(a, b));
	}
	// Generate 500 normal-normal range queries
	for (idx_t i = 0; i < 500; i++) {
		a = Radix::EncodeDouble(generate_double(-50, 50));
		b = Radix::EncodeDouble(generate_double(-50, 50));
		min_values.push_back(min(a, b));
		max_values.push_back(max(a, b));
	}
	// Generate 500 big-big range queries
	for (idx_t i = 0; i < 500; i++) {
		a = Radix::EncodeDouble(generate_double(FLT_MIN, FLT_MAX));
		b = Radix::EncodeDouble(generate_double(FLT_MIN, FLT_MAX));
		min_values.push_back(min(a, b));
		max_values.push_back(max(a, b));
	}
	for (idx_t i = 0; i < min_values.size(); i++) {
		int64_t low = Radix::EncodeDouble(min_values[i]);
		int64_t high = Radix::EncodeDouble(max_values[i]);
		int answer = full_scan<int64_t>(keys.get(), n, low, high);
		string query =
		    "SELECT COUNT(i) FROM numbers WHERE i >= " + to_string(low) + " and i <= " + to_string(high) + ";";
		result = con.Query(query);
		if (!CHECK_COLUMN(result, 0, {answer})) {
			cout << "Wrong answer on floating point real-small!" << std::endl << "Queries to reproduce:" << std::endl;
			cout << "CREATE TABLE numbers(i BIGINT);" << std::endl;
			for (idx_t k = 0; k < n; k++) {
				cout << "INSERT INTO numbers VALUES (" << keys[k] << ");" << std::endl;
			}
			cout << query << std::endl;
			REQUIRE(false);
		}
	}
	REQUIRE_NO_FAIL(con.Query("DROP INDEX i_index"));
	REQUIRE_NO_FAIL(con.Query("DROP TABLE numbers"));
}

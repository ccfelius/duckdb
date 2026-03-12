#define DUCKDB_EXTENSION_MAIN

#include "overload_extension_functions.hpp"
#include "duckdb.hpp"
#include "test_helpers.hpp"
#include "catch.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/main/client_data.hpp"

#include <duckdb/parser/parsed_data/create_scalar_function_info.hpp>
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/parser/parsed_data/create_schema_info.hpp"
#include "re2/re2.h"

using namespace duckdb;
using namespace std;

inline void SimpleScalarFunFirst(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &name_vector = args.data[0];
	UnaryExecutor::Execute<string_t, string_t>(name_vector, result, args.size(), [&](string_t name) {
		return StringVector::AddString(result, "First extension " + name.GetString() + " 🐥");
	});
}

inline void SimpleScalarFunSecond(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &name_vector = args.data[0];
	UnaryExecutor::Execute<string_t, string_t>(name_vector, result, args.size(), [&](string_t name) {
		return StringVector::AddString(result, "Second extension " + name.GetString() + " 🐥");
	});
}

static void SyncExtensions(Connection &con) {
	auto &context = con.context;

	if (context) {
		context->client_data->catalog_search_path->SyncCatalogSearchPath();
	}
}

static void FinishLoad(ExtensionLoader &loader) {
	auto &manager = ExtensionManager::Get(loader.GetDatabaseInstance());

	// we add the extension entry to the catalog
	if (loader.GetName() != CORE_FUNCTIONS) {
		CatalogSearchEntry entry(SYSTEM_CATALOG, loader.GetName());
		manager.AddSearchPath(entry);
	}
}

static void LoadInternalFirst(ExtensionLoader &loader) {
	// Register a scalar function
	auto simple_scalar_function =
	    ScalarFunction("simple", {LogicalType::VARCHAR}, LogicalType::VARCHAR, SimpleScalarFunFirst);
	loader.RegisterFunction(simple_scalar_function);
}

static void LoadInternalSecond(ExtensionLoader &loader) {
	// Register a scalar function
	auto simple_scalar_function =
	    ScalarFunction("simple", {LogicalType::VARCHAR}, LogicalType::VARCHAR, SimpleScalarFunSecond);
	loader.RegisterFunction(simple_scalar_function);
}

void CreateExtensionSchema(const string &name, DatabaseInstance &db) {
	auto &system_catalog = Catalog::GetSystemCatalog(db);
	auto data = CatalogTransaction::GetSystemTransaction(db);

	CreateSchemaInfo info;
	info.schema = name;
	info.internal = true;
	info.on_conflict = OnCreateConflict::IGNORE_ON_CONFLICT;
	system_catalog.CreateSchema(data, info);
}

std::string FirstExtension::Name() {
	return "first_extension";
}

std::string SecondExtension::Name() {
	return "second_extension";
}

void FirstExtension::Load(ExtensionLoader &loader) {
	LoadInternalFirst(loader);
}

void SecondExtension::Load(ExtensionLoader &loader) {
	LoadInternalSecond(loader);
}

extern "C" {

DUCKDB_CPP_EXTENSION_ENTRY(first_extension, loader) {
	LoadInternalFirst(loader);
	FinishLoad(loader);
}

DUCKDB_CPP_EXTENSION_ENTRY(second_extension, loader) {
	LoadInternalSecond(loader);
	FinishLoad(loader);
}
}

TEST_CASE("Test overlapping extension functions", "[extension_schema]") {
	DuckDB db(nullptr);
	Connection con(db);

	// first simulate the creation of extension schemas
	CreateExtensionSchema("first_extension", *db.instance);
	CreateExtensionSchema("second_extension", *db.instance);

	// Create a loader pointing to our database instance
	ExtensionLoader first_loader(*db.instance, "first_extension");

	// Load both extensions
	// Note that we need to first manually add
	// (1) the path to the catalog and
	// (2) sync the extension schema to add id to the search path
	first_extension_duckdb_cpp_init(first_loader);
	SyncExtensions(con);

	auto result = con.Query("SELECT simple('test')");
	REQUIRE_FALSE(result->HasError());

	// add the second extension
	ExtensionLoader second_loader(*db.instance, "second_extension");
	second_extension_duckdb_cpp_init(second_loader);
	SyncExtensions(con);

	// this throws an error, because we don't know which function to elect
	auto error_result = con.Query("SELECT simple('test')");
	REQUIRE(error_result->HasError());

	auto result_2 = con.Query("SELECT first_extension.simple('test')");
	REQUIRE_FALSE(result_2->HasError());
}

TEST_CASE("Test overlapping schema and extension names", "[extension_schema]") {
	DuckDB db(nullptr);
	Connection con(db);
	// first simulate the creation of extension schemas
	CreateExtensionSchema("first_extension", *db.instance);
	CreateExtensionSchema("second_extension", *db.instance);

	// Create a loader pointing to our database instance
	ExtensionLoader first_loader(*db.instance, "first_extension");
	ExtensionLoader second_loader(*db.instance, "second_extension");
	first_extension_duckdb_cpp_init(first_loader);
	second_extension_duckdb_cpp_init(second_loader);

	// sync extensions
	SyncExtensions(con);

	con.Query("SET schema = 'first_extension'");
	auto search_path = con.Query("SELECT CURRENT_SETTING('search_path')");
	std::cout << search_path->GetValue(0, 0).ToString() << std::endl;

	// Now 'simple' should resolve to first_extension without explicit qualification
	// auto result2 = con.Query("SELECT simple('test')");
}

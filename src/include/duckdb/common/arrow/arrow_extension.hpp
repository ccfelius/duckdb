//===----------------------------------------------------------------------===//
//                         DuckDB
//
// duckdb/common/arrow/arrow_extension.hpp
//
//
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb/main/query_result.hpp"
#include "duckdb/common/arrow/arrow_wrapper.hpp"
#include "duckdb/main/chunk_scan_state.hpp"
#include "duckdb/function/table/arrow/arrow_duck_schema.hpp"
#include <mutex>

namespace duckdb {
class ArrowSchemaMetadata;
struct DuckDBArrowSchemaHolder;

struct DBConfig;
struct ArrowExtensionInfo {
public:
	ArrowExtensionInfo() {
	}

	ArrowExtensionInfo(string extension_name, string vendor_name, string type_name, string arrow_format);

	hash_t GetHash() const;

	string ToString() const;

	string GetExtensionName() const;

	string GetVendorName() const;

	string GetTypeName() const;

	string GetArrowFormat() const;

	void SetArrowFormat(string arrow_format);

	bool IsCanonical() const;

	bool operator==(const ArrowExtensionInfo &other) const;

	//! Arrow Extension for non-canonical types.
	static constexpr const char *ARROW_EXTENSION_NON_CANONICAL = "arrow.opaque";

private:
	//! The extension name (e.g., 'arrow.uuid', 'arrow.opaque',...)
	string extension_name {};
	//! If the extension name is 'arrow.opaque' a vendor and type must be defined.
	//! The vendor_name is the system that produced the type (e.g., DuckDB)
	string vendor_name {};
	//! The type_name is the name of the type produced by the vendor (e.g., hugeint)
	string type_name {};
	//! The arrow format (e.g., z)
	string arrow_format {};
};

class ArrowExtension;

typedef void (*populate_arrow_schema_t)(DuckDBArrowSchemaHolder &root_holder, ArrowSchema &child,
                                        const LogicalType &type, ClientContext &context, ArrowExtension &extension);

typedef shared_ptr<ArrowType> (*get_type_t)(const string &format, const ArrowSchemaMetadata &schema_metadata);

class ArrowExtension {
public:
	ArrowExtension() {};
	//! We either have simple extensions where we only return one type
	ArrowExtension(string extension_name, string arrow_format, shared_ptr<ArrowType> type);
	ArrowExtension(string vendor_name, string type_name, string arrow_format, shared_ptr<ArrowType> type);

	//! We have complex extensions, where we can return multiple types, hence we must have callback functions to do so
	ArrowExtension(string extension_name, populate_arrow_schema_t populate_arrow_schema, get_type_t get_type,
	               shared_ptr<ArrowType> type);
	ArrowExtension(string vendor_name, string type_name, populate_arrow_schema_t populate_arrow_schema,
	               get_type_t get_type, shared_ptr<ArrowType> type);

	ArrowExtensionInfo GetInfo() const;

	shared_ptr<ArrowType> GetType(const string &format, const ArrowSchemaMetadata &schema_metadata) const;

	LogicalTypeId GetLogicalTypeId() const;

	LogicalType GetLogicalType() const;

	bool HasType() const;

	static void PopulateArrowSchema(DuckDBArrowSchemaHolder &root_holder, ArrowSchema &child,
	                                const LogicalType &duckdb_type, ClientContext &context, ArrowExtension &extension);

	//! (Optional) Callback to a function that sets up the arrow schema production
	populate_arrow_schema_t populate_arrow_schema = nullptr;
	//! (Optional) Callback to a function that sets up the arrow schema production
	get_type_t get_type = nullptr;

private:
	//! Extension Info from Arrow
	ArrowExtensionInfo extension_info;
	//! Arrow Type
	shared_ptr<ArrowType> type;
};

struct HashArrowExtension {
	size_t operator()(ArrowExtensionInfo const &arrow_extension_info) const noexcept {
		return arrow_extension_info.GetHash();
	}
};

struct TypeInfo {
	TypeInfo();
	explicit TypeInfo(const LogicalType &type);
	explicit TypeInfo(string alias);
	string alias;
	LogicalTypeId type;
	hash_t GetHash() const;
	bool operator==(const TypeInfo &other) const;
};

struct HashTypeInfo {
	size_t operator()(TypeInfo const &type_info) const noexcept {
		return type_info.GetHash();
	}
};

//! The set of encoding functions
struct ArrowExtensionSet {
	ArrowExtensionSet() {};
	static void Initialize(DBConfig &config);
	std::mutex lock;
	unordered_map<ArrowExtensionInfo, ArrowExtension, HashArrowExtension> extensions;
	unordered_map<TypeInfo, vector<ArrowExtensionInfo>, HashTypeInfo> type_to_info;
};

} // namespace duckdb

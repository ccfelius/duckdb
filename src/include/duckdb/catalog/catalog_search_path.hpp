//===----------------------------------------------------------------------===//
//                         DuckDB
//
// duckdb/catalog/catalog_search_path.hpp
//
//
//===----------------------------------------------------------------------===//

#pragma once

#include <functional>
#include "duckdb/common/enums/catalog_type.hpp"
#include "duckdb/common/string.hpp"
#include "duckdb/common/vector.hpp"
#include "duckdb/common/types/value.hpp"

namespace duckdb {

class ClientContext;

struct CatalogSearchEntry {
	CatalogSearchEntry(string catalog, string schema);

	string catalog;
	string schema;

public:
	string ToString() const;
	static string ListToString(const vector<CatalogSearchEntry> &input);
	static CatalogSearchEntry Parse(const string &input);
	static vector<CatalogSearchEntry> ParseList(const string &input);

private:
	static CatalogSearchEntry ParseInternal(const string &input, idx_t &pos);
	static string WriteOptionallyQuoted(const string &input);
};

enum class CatalogSetPathType { SET_SCHEMA, SET_SCHEMAS, SET_DIRECTLY };

//! The schema search path, in order by which entries are searched if no schema entry is provided
class CatalogSearchPath {
public:
	DUCKDB_API explicit CatalogSearchPath(ClientContext &client_p);
	DUCKDB_API CatalogSearchPath(ClientContext &client_p, vector<CatalogSearchEntry> entries);
	CatalogSearchPath(const CatalogSearchPath &other) = delete;

	DUCKDB_API void Set(CatalogSearchEntry new_value, CatalogSetPathType set_type);
	DUCKDB_API void Set(vector<CatalogSearchEntry> new_paths, CatalogSetPathType set_type);
	DUCKDB_API void Reset();

	DUCKDB_API vector<CatalogSearchEntry> Get() const;
	DUCKDB_API const vector<CatalogSearchEntry> &GetSetPaths() {
		this->set_and_extension_paths.clear();
		this->set_and_extension_paths.reserve(set_paths.size() + extension_paths.size());

		for (auto &path : set_paths) {
			this->set_and_extension_paths.push_back(path);
		}
		for (auto &path : extension_paths) {
			this->set_and_extension_paths.push_back(path);
		}
		return this->set_and_extension_paths;
	}
	void SyncExtensionPaths();
	DUCKDB_API const CatalogSearchEntry &GetDefault() const;
	DUCKDB_API vector<CatalogSearchEntry> GetExtensionPaths() const;
	//! FIXME: this method is deprecated
	DUCKDB_API string GetDefaultSchema(const string &catalog) const;
	DUCKDB_API string GetDefaultSchema(ClientContext &context, const string &catalog) const;
	DUCKDB_API string GetDefaultCatalog(const string &schema) const;

	DUCKDB_API vector<string> GetSchemasForCatalog(const string &catalog) const;
	DUCKDB_API vector<string> GetCatalogsForSchema(const string &schema) const;

	DUCKDB_API bool SchemaInSearchPath(ClientContext &context, const string &catalog_name,
	                                   const string &schema_name) const;

private:
	//! Set paths without checking if they exist
	void SetPathsInternal(vector<CatalogSearchEntry> new_paths);
	string GetSetName(CatalogSetPathType set_type);

private:
	ClientContext &context;
	vector<CatalogSearchEntry> paths;
	//! Only the paths that were explicitly set (minus the always included paths)
	vector<CatalogSearchEntry> set_paths;
	vector<CatalogSearchEntry> extension_paths;
	vector<CatalogSearchEntry> set_and_extension_paths;
	//! Only the paths that are related to extensions
	// vector<CatalogSearchEntry> extension_paths;
};

} // namespace duckdb

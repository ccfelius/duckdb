#include "duckdb/catalog/catalog_search_path.hpp"
#include "duckdb/catalog/default/default_schemas.hpp"

#include "duckdb/catalog/catalog.hpp"
#include "duckdb/common/constants.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/database_manager.hpp"
#include "duckdb/main/extension_manager.hpp"

#include "duckdb/common/exception/parser_exception.hpp"

namespace duckdb {
CatalogSearchEntry::CatalogSearchEntry(string catalog_p, string schema_p)
    : catalog(std::move(catalog_p)), schema(std::move(schema_p)) {
}

string CatalogSearchEntry::ToString() const {
	if (catalog.empty()) {
		return WriteOptionallyQuoted(schema);
	} else {
		return WriteOptionallyQuoted(catalog) + "." + WriteOptionallyQuoted(schema);
	}
}

string CatalogSearchEntry::WriteOptionallyQuoted(const string &input) {
	for (idx_t i = 0; i < input.size(); i++) {
		if (input[i] == '.' || input[i] == ',' || input[i] == '"') {
			return "\"" + StringUtil::Replace(input, "\"", "\"\"") + "\"";
		}
	}
	return input;
}

string CatalogSearchEntry::ListToString(const vector<CatalogSearchEntry> &input) {
	string result;
	for (auto &entry : input) {
		if (!result.empty()) {
			result += ",";
		}
		result += entry.ToString();
	}
	return result;
}

CatalogSearchEntry CatalogSearchEntry::ParseInternal(const string &input, idx_t &idx) {
	string catalog;
	string schema;
	string entry;
	bool finished = false;
normal:
	for (; idx < input.size(); idx++) {
		if (input[idx] == '"') {
			idx++;
			goto quoted;
		} else if (input[idx] == '.') {
			goto separator;
		} else if (input[idx] == ',') {
			finished = true;
			goto separator;
		}
		entry += input[idx];
	}
	finished = true;
	goto separator;
quoted:
	//! look for another quote
	for (; idx < input.size(); idx++) {
		if (input[idx] == '"') {
			//! unquote
			idx++;
			if (idx < input.size() && input[idx] == '"') {
				// escaped quote
				entry += input[idx];
				continue;
			}
			goto normal;
		}
		entry += input[idx];
	}
	throw ParserException("Unterminated quote in qualified name!");
separator:
	if (entry.empty()) {
		throw ParserException("Unexpected dot - empty CatalogSearchEntry");
	}
	if (schema.empty()) {
		// if we parse one entry it is the schema
		schema = std::move(entry);
	} else if (catalog.empty()) {
		// if we parse two entries it is [catalog.schema]
		catalog = std::move(schema);
		schema = std::move(entry);
	} else {
		throw ParserException("Too many dots - expected [schema] or [catalog.schema] for CatalogSearchEntry");
	}
	entry = "";
	idx++;
	if (finished) {
		goto final;
	}
	goto normal;
final:
	if (schema.empty()) {
		throw ParserException("Unexpected end of entry - empty CatalogSearchEntry");
	}
	return CatalogSearchEntry(std::move(catalog), std::move(schema));
}

CatalogSearchEntry CatalogSearchEntry::Parse(const string &input) {
	idx_t pos = 0;
	auto result = ParseInternal(input, pos);
	if (pos < input.size()) {
		throw ParserException("Failed to convert entry \"%s\" to CatalogSearchEntry - expected a single entry", input);
	}
	return result;
}

vector<CatalogSearchEntry> CatalogSearchEntry::ParseList(const string &input) {
	idx_t pos = 0;
	vector<CatalogSearchEntry> result;
	while (pos < input.size()) {
		auto entry = ParseInternal(input, pos);
		result.push_back(entry);
	}
	return result;
}

void CatalogSearchPath::SyncExtensionPaths() {
	auto &extension_manager = ExtensionManager::Get(context);
	auto extensions = extension_manager.GetExtensionSearchPaths();

	vector<CatalogSearchEntry> extension_entries;
	for (auto &entry : extensions) {
		extension_entries.emplace_back(entry);
	}

	if (extension_entries.empty()) {
		return;
	}

	SetPathsInternal(std::move(extension_entries), CatalogSearchPathType::EXTENSION_PATH);
}

CatalogSearchPath::CatalogSearchPath(ClientContext &context_p, vector<CatalogSearchEntry> entries)
    : context(context_p) {
	SetPathsInternal(CatalogSearchPathType::INTERNAL_PATH);
	SetPathsInternal(std::move(entries), CatalogSearchPathType::USER_PATH);
	// sync and set extension paths
	SyncExtensionPaths();
}

CatalogSearchPath::CatalogSearchPath(ClientContext &context_p) : CatalogSearchPath(context_p, {}) {
}

void CatalogSearchPath::Reset() {
	SetPathsInternal(CatalogSearchPathType::INTERNAL_PATH);
	user_paths.clear();
	extension_paths.clear();
}

string CatalogSearchPath::GetSetName(CatalogSetPathType set_type) {
	switch (set_type) {
	case CatalogSetPathType::SET_SCHEMA:
		return "SET schema";
	case CatalogSetPathType::SET_SCHEMAS:
		return "SET search_path";
	default:
		throw InternalException("Unrecognized CatalogSetPathType");
	}
}

void CatalogSearchPath::Set(vector<CatalogSearchEntry> new_paths, CatalogSetPathType set_type,
                            CatalogSearchPathType search_path_type) {
	if (set_type == CatalogSetPathType::SET_SCHEMA && new_paths.size() != 1) {
		throw CatalogException("%s can set only 1 schema. This has %d", GetSetName(set_type), new_paths.size());
	}
	for (auto &path : new_paths) {
		if (set_type == CatalogSetPathType::SET_DIRECTLY) {
			if (path.catalog.empty() || path.schema.empty()) {
				throw InternalException("SET_WITHOUT_VERIFICATION requires a fully qualified set path");
			}
			continue;
		}
		auto schema_entry = Catalog::GetSchema(context, path.catalog, path.schema, OnEntryNotFound::RETURN_NULL);
		if (schema_entry) {
			// we are setting a schema - update the catalog and schema
			if (path.catalog.empty()) {
				path.catalog = GetDefault().catalog;
			}
			continue;
		}
		// only schema supplied - check if this is a catalog instead
		if (path.catalog.empty()) {
			auto catalog = Catalog::GetCatalogEntry(context, path.schema);
			if (catalog) {
				auto schema = catalog->GetSchema(context, catalog->GetDefaultSchema(), OnEntryNotFound::RETURN_NULL);
				if (schema) {
					path.catalog = std::move(path.schema);
					path.schema = schema->name;
					continue;
				}
			}
		}
		throw CatalogException("%s: No catalog + schema named \"%s\" found.", GetSetName(set_type), path.ToString());
	}
	if (set_type == CatalogSetPathType::SET_SCHEMA) {
		if (new_paths[0].catalog == TEMP_CATALOG || new_paths[0].catalog == SYSTEM_CATALOG) {
			throw CatalogException("%s cannot be set to internal schema \"%s\"", GetSetName(set_type),
			                       new_paths[0].catalog);
		}
	}

	SetPathsInternal(new_paths, search_path_type);
}

void CatalogSearchPath::Set(CatalogSearchEntry new_value, CatalogSetPathType set_type,
                            CatalogSearchPathType search_path_type) {
	vector<CatalogSearchEntry> new_paths {std::move(new_value)};
	Set(std::move(new_paths), set_type);
}

vector<CatalogSearchEntry> CatalogSearchPath::GetAllSearchPaths() const {
	auto total_size = internal_paths.size() + user_paths.size() + extension_paths.size();

	vector<CatalogSearchEntry> paths;
	paths.reserve(total_size);
	for (auto &path : internal_paths) {
		if (path.schema.empty()) {
			continue;
		}
		paths.emplace_back(path);
	}
	for (auto &path : user_paths) {
		if (path.schema.empty()) {
			continue;
		}
		paths.emplace_back(path);
	}
	for (auto &path : extension_paths) {
		if (path.schema.empty()) {
			continue;
		}
		paths.emplace_back(path);
	}

	return paths;
}
vector<CatalogSearchEntry> CatalogSearchPath::Get(CatalogSearchPathType type) const {
	vector<CatalogSearchEntry> res;

	switch (type) {
	case CatalogSearchPathType::INTERNAL_PATH:
		for (auto &path : internal_paths) {
			if (path.schema.empty()) {
				continue;
			}
			res.emplace_back(path);
		}
		break;

	case CatalogSearchPathType::EXTENSION_PATH:
		for (auto &path : extension_paths) {
			if (path.schema.empty()) {
				continue;
			}
			res.emplace_back(path);
		}
		break;

	case CatalogSearchPathType::USER_PATH:
		for (auto &path : user_paths) {
			if (path.schema.empty()) {
				continue;
			}
			res.emplace_back(path);
		}
		break;
	default:
		throw InvalidInputException("Unrecognized CatalogSearchPathType");
	}

	return res;
}

vector<CatalogSearchEntry> CatalogSearchPath::GetInternalPaths() const {
	return Get(CatalogSearchPathType::INTERNAL_PATH);
}

vector<CatalogSearchEntry> CatalogSearchPath::GetExtensionPaths() const {
	return Get(CatalogSearchPathType::EXTENSION_PATH);
}

vector<CatalogSearchEntry> CatalogSearchPath::GetUserPaths() const {
	return Get(CatalogSearchPathType::USER_PATH);
}

string CatalogSearchPath::GetDefaultSchema(ClientContext &context, const string &catalog) const {
	for (auto &path : internal_paths) {
		if (path.catalog == TEMP_CATALOG) {
			continue;
		}
		if (StringUtil::CIEquals(path.catalog, catalog)) {
			return path.schema;
		}
	}
	for (auto &path : user_paths) {
		if (StringUtil::CIEquals(path.catalog, catalog)) {
			return path.schema;
		}
	}
	// Extensions do not have a default schema?
	auto catalog_entry = Catalog::GetCatalogEntry(context, catalog);
	if (catalog_entry) {
		return catalog_entry->GetDefaultSchema();
	}
	return DEFAULT_SCHEMA;
}

string CatalogSearchPath::GetDefaultCatalog(const string &schema) const {
	if (DefaultSchemaGenerator::IsDefaultSchema(schema)) {
		return SYSTEM_CATALOG;
	}
	for (auto &path : internal_paths) {
		if (path.catalog == TEMP_CATALOG) {
			continue;
		}
		if (StringUtil::CIEquals(path.schema, schema)) {
			return path.catalog;
		}
	}
	for (auto &path : user_paths) {
		if (StringUtil::CIEquals(path.schema, schema)) {
			return path.catalog;
		}
	}
	return INVALID_CATALOG;
}

vector<string> CatalogSearchPath::GetCatalogsForSchema(const string &schema) const {
	vector<string> catalogs;
	if (DefaultSchemaGenerator::IsDefaultSchema(schema)) {
		catalogs.push_back(SYSTEM_CATALOG);
	} else {
		for (auto &path : internal_paths) {
			if (StringUtil::CIEquals(path.schema, schema) || path.schema.empty()) {
				catalogs.push_back(path.catalog);
			}
		}
		for (auto &path : user_paths) {
			if (StringUtil::CIEquals(path.schema, schema) || path.schema.empty()) {
				catalogs.push_back(path.catalog);
			}
		}
		// not sure if this is also necessary?
		for (auto &path : extension_paths) {
			if (StringUtil::CIEquals(path.schema, schema)) {
				catalogs.push_back(path.catalog);
			}
		}
	}
	return catalogs;
}

vector<string> CatalogSearchPath::GetSchemasForCatalog(const string &catalog) const {
	vector<string> schemas;
	for (auto &path : user_paths) {
		if (!path.schema.empty() && StringUtil::CIEquals(path.catalog, catalog)) {
			schemas.push_back(path.schema);
		}
	}
	for (auto &path : internal_paths) {
		if (!path.schema.empty() && StringUtil::CIEquals(path.catalog, catalog)) {
			schemas.push_back(path.schema);
		}
	}
	for (auto &path : extension_paths) {
		if (!path.schema.empty() && StringUtil::CIEquals(path.catalog, catalog)) {
			schemas.push_back(path.schema);
		}
	}
	return schemas;
}

const CatalogSearchEntry &CatalogSearchPath::GetDefault() const {
	// FIXME; do not hardcode the indices
	D_ASSERT(internal_paths.size() >= 2);
	D_ASSERT(!internal_paths[1].schema.empty());

	if (!user_paths.empty()) {
		return user_paths[0];
	}

	D_ASSERT(!internal_paths.empty());
	return internal_paths[1];
}

// TODO try to understand this logic
// const CatalogSearchEntry &CatalogSearchPath::GetDefault() const {
// 	D_ASSERT(paths.size() >= 2);
// 	D_ASSERT(!paths[1].schema.empty());
// 	return paths[1];
// this can be invalid (internal paths)
// or it can be the last appended user path?
// }

void CatalogSearchPath::AddExtension(const string &extension_name) {
	CatalogSearchEntry entry(SYSTEM_CATALOG, extension_name);
	SetPathsInternal({entry}, CatalogSearchPathType::EXTENSION_PATH);
}

void CatalogSearchPath::SetPaths(const vector<CatalogSearchEntry> &new_paths, CatalogSearchPathType type) {
	// paths always get OVERWRITTEN

	if (new_paths.empty()) {
		return;
	}

	switch (type) {
	case CatalogSearchPathType::EXTENSION_PATH:
		extension_paths.clear();
		extension_paths.reserve(new_paths.size());
		for (auto &path : new_paths) {
			extension_paths.push_back(path);
		}
		this->extension_paths = std::move(new_paths);
		break;
	case CatalogSearchPathType::USER_PATH:
		user_paths.clear();
		user_paths.reserve(new_paths.size());
		for (auto &path : new_paths) {
			user_paths.push_back(path);
		}
		this->user_paths = std::move(new_paths);
		break;
	default:
		throw InvalidInputException("Unrecognized CatalogSearchPathType");
	}
}

void CatalogSearchPath::SetInternalPaths() {
	this->internal_paths.clear();
	this->internal_paths.reserve(INTERNAL_PATH_SIZE);

	vector<CatalogSearchEntry> internal_entries;
	internal_entries.push_back(CatalogSearchEntry(TEMP_CATALOG, DEFAULT_SCHEMA));
	internal_entries.push_back(CatalogSearchEntry(INVALID_CATALOG, DEFAULT_SCHEMA));
	internal_entries.push_back(CatalogSearchEntry(SYSTEM_CATALOG, DEFAULT_SCHEMA));
	internal_entries.push_back(CatalogSearchEntry(SYSTEM_CATALOG, "pg_catalog"));

	this->internal_paths = internal_entries;
}

void CatalogSearchPath::SetPathsInternal(CatalogSearchPathType type) {
	if (type != CatalogSearchPathType::INTERNAL_PATH) {
		throw InvalidInputException("CatalogSearchPath type must be INTERNAL_PATH");
	}
	SetInternalPaths();
}

void CatalogSearchPath::SetPathsInternal(vector<CatalogSearchEntry> new_paths, CatalogSearchPathType search_path_type) {
	switch (search_path_type) {
	case CatalogSearchPathType::USER_PATH:
		SetPaths(new_paths, CatalogSearchPathType::USER_PATH);
		break;
	case CatalogSearchPathType::EXTENSION_PATH:
		SetPaths(new_paths, CatalogSearchPathType::EXTENSION_PATH);
		break;
	default:
		throw InvalidInputException("CatalogSearchPath type must be USER_PATH or EXTENSION_PATH");
	}
}

bool CatalogSearchPath::SchemaInSearchPath(ClientContext &context, const string &catalog_name,
                                           const string &schema_name) const {
	for (auto &path : internal_paths) {
		if (!StringUtil::CIEquals(path.schema, schema_name)) {
			continue;
		}
		if (StringUtil::CIEquals(path.catalog, catalog_name)) {
			return true;
		}
		if (IsInvalidCatalog(path.catalog) &&
		    StringUtil::CIEquals(catalog_name, DatabaseManager::GetDefaultDatabase(context))) {
			return true;
		}
	}
	for (auto &path : user_paths) {
		if (!StringUtil::CIEquals(path.schema, schema_name)) {
			continue;
		}
		if (StringUtil::CIEquals(path.catalog, catalog_name)) {
			return true;
		}
		if (IsInvalidCatalog(path.catalog) &&
		    StringUtil::CIEquals(catalog_name, DatabaseManager::GetDefaultDatabase(context))) {
			return true;
		}
	}

	for (auto &path : extension_paths) {
		if (!StringUtil::CIEquals(path.schema, schema_name)) {
			continue;
		}
		if (StringUtil::CIEquals(path.catalog, catalog_name)) {
			return true;
		}
		if (IsInvalidCatalog(path.catalog) &&
		    StringUtil::CIEquals(catalog_name, DatabaseManager::GetDefaultDatabase(context))) {
			return true;
		}
	}
	return false;
}

} // namespace duckdb

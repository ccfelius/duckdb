//===----------------------------------------------------------------------===//
//                         DuckDB
//
// duckdb/catalog/standard_entry.hpp
//
//
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb/catalog/catalog_entry.hpp"
#include "duckdb/catalog/dependency_list.hpp"

namespace duckdb {
class SchemaCatalogEntry;

//! A StandardEntry is a catalog entry that is a member of a schema
class StandardEntry : public InCatalogEntry {
public:
	StandardEntry(CatalogType type, SchemaCatalogEntry &schema, Catalog &catalog, string name)
	    : InCatalogEntry(type, catalog, name), schema(schema) {
	}
	~StandardEntry() override {
	}

	//! The schema the entry belongs to
	SchemaCatalogEntry &schema;
	//! The dependencies of the entry, can be empty
	PhysicalDependencyList dependencies;

public:
	SchemaCatalogEntry &ParentSchema() override {
		return schema;
	}
};

} // namespace duckdb

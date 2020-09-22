//===----------------------------------------------------------------------===//
//                         DuckDB
//
// duckdb/parser/parsed_data/create_info.hpp
//
//
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb/parser/parsed_data/parse_info.hpp"
#include "duckdb/common/enums/catalog_type.hpp"

namespace duckdb {

enum class OnCreateConflict : uint8_t {
	// Standard: throw error
	ERROR_ON_CONFLICT,
	// CREATE IF NOT EXISTS, silently do nothing on conflict
	IGNORE_ON_CONFLICT,
	// CREATE OR REPLACE
	REPLACE_ON_CONFLICT
};

struct CreateInfo : public ParseInfo {
	CreateInfo(CatalogType type, string schema = DEFAULT_SCHEMA)
	    : type(type), schema(schema), on_conflict(OnCreateConflict::ERROR_ON_CONFLICT), temporary(false) {
	}
	virtual ~CreateInfo() {
	}

	//! The to-be-created catalog type
	CatalogType type;
	//! The schema name of the entry
	string schema;
	//! What to do on create conflict
	OnCreateConflict on_conflict;
	//! Whether or not the entry is temporary
	bool temporary;
};

} // namespace duckdb

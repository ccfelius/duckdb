//===----------------------------------------------------------------------===//
//                         DuckDB
//
// duckdb/function/table/orchestrate.hpp
//
//
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb/function/built_in_functions.hpp"

namespace duckdb {

struct OrchestrateTableFunction {
	static void RegisterFunction(BuiltinFunctions &set);
};

} // namespace duckdb

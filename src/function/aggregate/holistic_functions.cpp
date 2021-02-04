#include "duckdb/function/aggregate/holistic_functions.hpp"

namespace duckdb {

void BuiltinFunctions::RegisterHolisticAggregates() {
	Register<QuantileFun>();
	Register<ApproximateQuantileFun>();
	Register<ReservoirQuantileFun>();
}

} // namespace duckdb

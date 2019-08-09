#include "function/scalar_function/math_functions.hpp"
#include "common/vector_operations/vector_operations.hpp"

using namespace std;

namespace duckdb {

void floor_function(ExpressionExecutor &exec, Vector inputs[], index_t input_count, BoundFunctionExpression &expr,
                    Vector &result) {
	assert(input_count == 1);
	result.Initialize(inputs[0].type);
	VectorOperations::Floor(inputs[0], result);
}

}

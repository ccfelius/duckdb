//===----------------------------------------------------------------------===//
//                         DuckDB
//
// duckdb_python/pyrelation.hpp
//
//
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb_python/pybind11/pybind_wrapper.hpp"
#include "duckdb.hpp"
#include "duckdb/common/string.hpp"
#include "duckdb/parser/parsed_expression.hpp"
#include "duckdb/parser/expression/constant_expression.hpp"
#include "duckdb/parser/expression/columnref_expression.hpp"
#include "duckdb/parser/expression/function_expression.hpp"
#include "duckdb_python/python_conversion.hpp"
#include "duckdb_python/pyconnection/pyconnection.hpp"
#include "duckdb_python/pytype.hpp"

namespace duckdb {

// pyduckdb.Value class
struct PythonValue : py::object {
public:
	PythonValue(const py::object &o) : py::object(o, borrowed_t {}) {
	}
	using py::object::object;

public:
	static bool check_(const py::handle &object) { // NOLINT
		auto &import_cache = *DuckDBPyConnection::ImportCache();
		return py::isinstance(object, import_cache.pyduckdb().value());
	}
};

struct DuckDBPyExpression : public std::enable_shared_from_this<DuckDBPyExpression> {
public:
	explicit DuckDBPyExpression(unique_ptr<ParsedExpression> expr);

public:
	std::shared_ptr<DuckDBPyExpression> shared_from_this() {
		return std::enable_shared_from_this<DuckDBPyExpression>::shared_from_this();
	}

public:
	static void Initialize(py::module_ &m);

	string Type() const;

	string ToString() const;
	void Print() const;
	shared_ptr<DuckDBPyExpression> Add(const DuckDBPyExpression &other);
	shared_ptr<DuckDBPyExpression> Negate();
	shared_ptr<DuckDBPyExpression> Subtract(const DuckDBPyExpression &other);
	shared_ptr<DuckDBPyExpression> Multiply(const DuckDBPyExpression &other);
	shared_ptr<DuckDBPyExpression> Division(const DuckDBPyExpression &other);
	shared_ptr<DuckDBPyExpression> FloorDivision(const DuckDBPyExpression &other);
	shared_ptr<DuckDBPyExpression> Modulo(const DuckDBPyExpression &other);
	shared_ptr<DuckDBPyExpression> Power(const DuckDBPyExpression &other);
	shared_ptr<DuckDBPyExpression> Equality(const DuckDBPyExpression &other);
	shared_ptr<DuckDBPyExpression> Inequality(const DuckDBPyExpression &other);
	shared_ptr<DuckDBPyExpression> GreaterThan(const DuckDBPyExpression &other);
	shared_ptr<DuckDBPyExpression> GreaterThanOrEqual(const DuckDBPyExpression &other);
	shared_ptr<DuckDBPyExpression> LessThan(const DuckDBPyExpression &other);
	shared_ptr<DuckDBPyExpression> LessThanOrEqual(const DuckDBPyExpression &other);

	shared_ptr<DuckDBPyExpression> SetAlias(const string &alias) const;
	shared_ptr<DuckDBPyExpression> When(const DuckDBPyExpression &condition, const DuckDBPyExpression &value);
	shared_ptr<DuckDBPyExpression> Else(const DuckDBPyExpression &value);
	shared_ptr<DuckDBPyExpression> Cast(const DuckDBPyType &type) const;

public:
	const ParsedExpression &GetExpression() const;

public:
	static shared_ptr<DuckDBPyExpression> BinaryFunctionExpression(const string &function_name,
	                                                               shared_ptr<DuckDBPyExpression> arg_one,
	                                                               shared_ptr<DuckDBPyExpression> arg_two);
	static shared_ptr<DuckDBPyExpression> StarExpression();
	static shared_ptr<DuckDBPyExpression> ColumnExpression(const string &function_name);
	static shared_ptr<DuckDBPyExpression> ConstantExpression(const PythonValue &value);
	static shared_ptr<DuckDBPyExpression> CaseExpression(const DuckDBPyExpression &condition,
	                                                     const DuckDBPyExpression &value);
	static shared_ptr<DuckDBPyExpression> FunctionExpression(const string &function_name, py::args args);

private:
	static shared_ptr<DuckDBPyExpression> InternalFunctionExpression(const string &function_name,
	                                                                 vector<unique_ptr<ParsedExpression>> children,
	                                                                 bool is_operator = false);
	static shared_ptr<DuckDBPyExpression> BinaryOperator(const string &function_name, const DuckDBPyExpression &arg_one,
	                                                     const DuckDBPyExpression &arg_two);
	static shared_ptr<DuckDBPyExpression> ComparisonExpression(ExpressionType type, const DuckDBPyExpression &left,
	                                                           const DuckDBPyExpression &right);
	static shared_ptr<DuckDBPyExpression> InternalWhen(unique_ptr<duckdb::CaseExpression> expr,
	                                                   const DuckDBPyExpression &condition,
	                                                   const DuckDBPyExpression &value);
	void AssertCaseExpression() const;

private:
	unique_ptr<ParsedExpression> expression;
};

} // namespace duckdb

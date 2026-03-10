#pragma once

#include "duckdb.hpp"

namespace duckdb {

class FirstExtension : public Extension {
public:
	void Load(ExtensionLoader &db) override;
	std::string Name() override;
};

class SecondExtension : public Extension {
public:
	void Load(ExtensionLoader &db) override;
	std::string Name() override;
};

} // namespace duckdb
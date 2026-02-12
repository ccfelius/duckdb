
namespace duckdb {

class ExtensionFunction {
	//
	ExtensionFunction() {
	}

private:
	string_t function_name;
	// maybe do the args for later?
	// or just do the args load whenever / wherever
	// ordered_map<LogicalType> function_args;
};

class ExtensionFunctionMappingEntry {
public:
public:
	// to support the load <function> from <extension> syntax
	// maybe this needs to be private?
	bool is_loaded;

private:
	unique_ptr<ExtensionFunction> extension_function;
	vector<string> schema_names;
	vector<string> extension_names;

	// 	string alias;
	// full path
	// any other shortcuts? a ptr to the actual function?
};

class ExtensionFunctionMapping {
	// the extension function mapping is a
	// ExtensionFunction, Schema Name,
	// extension name
	// alias
	//
	// public:
	// ExtensionFunctionMapping : ExtensionFunctionMapping();
	//
	// public:
	// 	RegisterExtensionFunction(unique_ptr<ExtensionFunction> function);
	// 	ExtensionFunctionMappingEntry GetEntry(string function_name, string schema_name, string extension_name);
};

} // namespace duckdb

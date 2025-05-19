#include "duckdb/common/exception.hpp"
#include "duckdb/main/secret/secret.hpp"
#include "duckdb/main/extension_util.hpp"

namespace core {

// This code partly copied / inspired by the gsheets extension for duckdb
static void AddSecretParameter(const std::string &key, const CreateSecretInput &input, KeyValueSecret &result) {
	// this method checks whether a secret_param is present in the secret_map
	auto val = input.options.find(key);
	// does this also take a key, value or list struct?
	if (val != input.options.end()) {
		result.secret_map[key] = val->second;
	}
}

static void RegisterCommonSecretParameters(CreateSecretFunction &function) {
	function.named_parameters["token"] = LogicalType::VARCHAR;
	function.named_parameters["length"] = LogicalType::INTEGER;
}

static void RedactSensitiveKeys(KeyValueSecret &result) {
	result.redact_keys.insert("token");
}

static unique_ptr<BaseSecret> CreateKeyEncryptionKey(ClientContext &context, CreateSecretInput &input) {

	auto scope = input.scope;

	// create new KV secret
	auto result = make_uniq<KeyValueSecret>(scope, input.type, input.provider, input.name);

	// check key size
	auto length = input.options["length"].GetValue<uint32_t>();

	if (!CheckKeySize(length)) {
		throw InvalidInputException("Invalid size for encryption key: '%d', only a length of 16 bytes is supported",
		                            length);
	}

	// get the other results from the user input
	auto token = input.options["token"].GetValue<std::string>();

	// Store the token in the secret
	result->secret_map["token"] = Value(token);
	result->secret_map["length"] = Value(to_string(length));

	// Hide (redact) sensitive information
	RedactSensitiveKeys(*result);

	return std::move(result);
}

void CoreSecretFunctions::RegisterStoreEncryptSecretFunction(DatabaseInstance &db) {

	string type = "vcrypt";

	// Register the new secret type
	SecretType secret_type;
	secret_type.name = type;
	secret_type.deserializer = KeyValueSecret::Deserialize<KeyValueSecret>;
	secret_type.default_provider = "client";
	ExtensionUtil::RegisterSecretType(db, secret_type);

	// Register the key_encryption_key secret provider
	CreateSecretFunction key_encryption_key = {type, "client", CreateKeyEncryptionKey};
	RegisterCommonSecretParameters(key_encryption_key);
	ExtensionUtil::RegisterFunction(db, key_encryption_key);
}

} // namespace core

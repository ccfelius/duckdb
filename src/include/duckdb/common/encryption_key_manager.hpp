//===----------------------------------------------------------------------===//
//                         DuckDB
//
// duckdb/common/encryption_key_manager.hpp
//
//
//===----------------------------------------------------------------------===//

#pragma once

#include "duckdb/common/helper.hpp"
#include "duckdb/common/types/value.hpp"
#include "duckdb/common/unordered_map.hpp"

#ifndef DUCKDB_AMALGAMATION
#include "duckdb/storage/object_cache.hpp"
#endif

namespace duckdb {

class EncryptionKey {

public:
	explicit EncryptionKey(const uint8_t encryption_key[32]);

	~EncryptionKey();

	EncryptionKey(const EncryptionKey &) = delete;
	EncryptionKey &operator=(const EncryptionKey &) = delete;

	EncryptionKey(EncryptionKey &&) noexcept = default;
	EncryptionKey &operator=(EncryptionKey &&) noexcept = default;

public:
	const uint8_t* Get() const {
		return key;
	}

private:
	uint8_t key[32];

private:
	static void LockEncryptionKey(const uint8_t key[32]);
	static void UnlockEncryptionKey(const uint8_t key_p[32]);
};

class EncryptionKeyManager : public ObjectCacheEntry {

public:
	explicit EncryptionKeyManager() = default;
	~EncryptionKeyManager() override = default;

public:
	static void Initialize(ObjectCache &cache);
	static EncryptionKeyManager &GetInternal(ObjectCache &cache);
	static EncryptionKeyManager &Get(ClientContext &context);
	static EncryptionKeyManager &Get(DatabaseInstance &db);

public:
	void AddKey(const string &key_name, uint8_t &key, bool wipe = true);
	bool HasKey(const string &key_name) const;
	void DeleteKey(const string &key_name);
	const unique_ptr<EncryptionKey> &GetKey(const string &key_name) const;

public:
	static string ObjectType();
	string GetObjectType() override;

public:
	//! constants
	static constexpr idx_t KEY_ID_BYTES = 8;
	static constexpr idx_t DERIVED_KEY_LENGTH = 32;

public:
	static std::array<uint8_t, EncryptionKeyManager::DERIVED_KEY_LENGTH> DeriveKey(const string &user_key, data_ptr_t salt);
	static std::array<uint8_t, DERIVED_KEY_LENGTH> KeyDerivationFunctionSHA256(const string &user_key, data_ptr_t salt);
	static string GenerateRandomKey();
	static string GenerateRandomKeyID();

private:
	duckdb::unordered_map<std::string, unique_ptr<EncryptionKey>> derived_keys;
};

} // namespace duckdb

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
#include "duckdb/common/types.hpp"

#ifndef DUCKDB_AMALGAMATION
#include "duckdb/storage/object_cache.hpp"
#endif

namespace duckdb {

class EncryptionKey {

public:
	explicit EncryptionKey(data_ptr_t encryption_key);
	~EncryptionKey();

	EncryptionKey(const EncryptionKey &) = delete;
	EncryptionKey &operator=(const EncryptionKey &) = delete;

	EncryptionKey(EncryptionKey &&) noexcept = default;
	EncryptionKey &operator=(EncryptionKey &&) noexcept = default;

public:
	const_data_ptr_t GetPtr() const {
		return key;
	}

private:
	uint8_t key[MainHeader::DEFAULT_ENCRYPTION_KEY_LENGTH];

private:
	static void LockEncryptionKey(data_ptr_t key);
	static void UnlockEncryptionKey(data_ptr_t key);
};

class MasterKey {

public:
	explicit MasterKey(data_ptr_t encryption_key, idx_t key_size_p)
	    : master_key(new data_t[key_size_p]), key_size(key_size_p) {};

	~MasterKey() {
		delete[] master_key;
	};

	MasterKey(const MasterKey &) = delete;
	MasterKey &operator=(const MasterKey &) = delete;

	MasterKey(MasterKey &&) noexcept = default;
	MasterKey &operator=(MasterKey &&) noexcept = default;

public:
	const_data_ptr_t GetPtr() const {
		return master_key;
	}

	idx_t GetSize() const {
		return key_size;
	}

private:
	data_t *master_key;
	idx_t key_size;

private:
	static void LockMasterKey(data_ptr_t key);
	static void UnlockMasterKey(data_ptr_t key);
};

class EncryptionKeyManager : public ObjectCacheEntry {

public:
	static EncryptionKeyManager &GetInternal(ObjectCache &cache);
	static EncryptionKeyManager &Get(ClientContext &context);
	static EncryptionKeyManager &Get(DatabaseInstance &db);

public:
	void AddKey(const string &key_name, data_ptr_t key);
	void AddMasterKey(data_ptr_t master_key);
	bool HasKey(const string &key_name) const;
	void DeleteKey(const string &key_name);
	const_data_ptr_t GetKey(const string &key_name) const;

public:
	static string ObjectType();
	string GetObjectType() override;

public:
	void SetMasterKey() {
		master_key_initialized = true;
	}

	void UnSetMasterKey() {
		master_key_initialized = false;
	}

	bool HasMasterKey() const {
		return master_key_initialized;
	}

public:
	static void DeriveKey(const string &user_key, data_ptr_t salt, data_ptr_t derived_key);
	static void DeriveKey(data_ptr_t user_key, data_ptr_t salt, data_ptr_t derived_key);
	static void KeyDerivationFunctionSHA256(data_ptr_t user_key, idx_t user_key_size, data_ptr_t salt,
	                                        data_ptr_t derived_key);
	static string GenerateRandomKeyID();

public:
	//! constants
	static constexpr idx_t KEY_ID_BYTES = 8;
	static constexpr idx_t DERIVED_KEY_LENGTH = 32;

private:
	std::unordered_map<std::string, EncryptionKey> derived_keys;
	MasterKey master_key;
	bool master_key_initialized = false;
};

} // namespace duckdb

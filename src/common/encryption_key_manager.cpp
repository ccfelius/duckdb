#include "duckdb/common/encryption_key_manager.hpp"
#include "mbedtls_wrapper.hpp"
#include "duckdb/common/windows.hpp"
#include <sys/mman.h>

namespace duckdb {

EncryptionKey::EncryptionKey(const uint8_t key_p[32]) {
	memcpy(key, key_p, 32);
	// Lock the encryption key
	LockEncryptionKey(key);
}

// destructor
EncryptionKey::~EncryptionKey() {
	if (key){
		UnlockEncryptionKey(key);
	}
}

void EncryptionKey::LockEncryptionKey(const uint8_t key[32]) {
#if defined(_WIN32)
		VirtualLock(reinterpret_cast<void *>(const_cast<uint8_t *>(key)), EncryptionKeyManager::DERIVED_KEY_LENGTH);
#else
		mlock(reinterpret_cast<void *>(const_cast<uint8_t *>(key)), EncryptionKeyManager::DERIVED_KEY_LENGTH);
#endif
}

void EncryptionKey::UnlockEncryptionKey(const uint8_t key[32]) {
	memset(&key, 0, EncryptionKeyManager::DERIVED_KEY_LENGTH);
#if defined(_WIN32)
	VirtualUnlock(reinterpret_cast<void *>(const_cast<uint8_t *>(key)), EncryptionKeyManager::DERIVED_KEY_LENGTH);
#else
	munlock(reinterpret_cast<void *>(const_cast<uint8_t *>(key)), EncryptionKeyManager::DERIVED_KEY_LENGTH);
#endif
}

void EncryptionKeyManager::Initialize(ObjectCache &cache) {
	cache.Put(EncryptionKeyManager::ObjectType(), make_shared_ptr<EncryptionKeyManager>());
}

EncryptionKeyManager &EncryptionKeyManager::GetInternal(ObjectCache &cache) {
	if (!cache.Get<EncryptionKeyManager>(EncryptionKeyManager::ObjectType())) {
		Initialize(cache);
	}
	return *cache.Get<EncryptionKeyManager>(EncryptionKeyManager::ObjectType());
}

EncryptionKeyManager &EncryptionKeyManager::Get(ClientContext &context) {
	auto &cache = ObjectCache::GetObjectCache(context);
	return GetInternal(cache);
}

EncryptionKeyManager &EncryptionKeyManager::Get(DatabaseInstance &db) {
	auto &cache = db.GetObjectCache();
	return GetInternal(cache);
}

string EncryptionKeyManager::GenerateRandomKey() {
	uint8_t key_id[DERIVED_KEY_LENGTH];
	duckdb_mbedtls::MbedTlsWrapper::AESStateMBEDTLS::GenerateRandomDataStatic(key_id, DERIVED_KEY_LENGTH);
	string key_id_str(reinterpret_cast<const char *>(key_id), DERIVED_KEY_LENGTH);
	return key_id_str;
}

string EncryptionKeyManager::GenerateRandomKeyID() {
	uint8_t key_id[KEY_ID_BYTES];
	duckdb_mbedtls::MbedTlsWrapper::AESStateMBEDTLS::GenerateRandomDataStatic(key_id, KEY_ID_BYTES);
	string key_id_str(reinterpret_cast<const char *>(key_id), KEY_ID_BYTES);
	return key_id_str;
}

void EncryptionKeyManager::AddKey(const string &key_name, uint8_t &key, bool wipe) {
	// make sure the actual key is passed and accessed
	derived_keys.emplace(key_name, make_uniq<EncryptionKey>(key));
	if (wipe) {
		// wipe out the original key
		memset(&key, 0, DERIVED_KEY_LENGTH);
	}
}

bool EncryptionKeyManager::HasKey(const string &key_name) const {
	return derived_keys.find(key_name) != derived_keys.end();
}

const unique_ptr<EncryptionKey> &EncryptionKeyManager::GetKey(const string &key_name) const {
	if (!HasKey(key_name)) {
		throw IOException("Key ID not found in cache");
	};
	auto &key = derived_keys.at(key_name);
	return key;
}

void EncryptionKeyManager::DeleteKey(const string &key_name) {
	derived_keys.erase(key_name);
}

std::array<uint8_t, EncryptionKeyManager::DERIVED_KEY_LENGTH> EncryptionKeyManager::KeyDerivationFunctionSHA256(const string &user_key, data_ptr_t salt) {
	//! For now, we are only using SHA256 for key derivation
	duckdb_mbedtls::MbedTlsWrapper::SHA256State state;
	state.AddSalt(salt, MainHeader::SALT_LEN);
	state.AddString(user_key);
	auto derived_key = state.FinalizeArray();

	//! key_length is hardcoded to 32 bytes now
	D_ASSERT(derived_key.length() == MainHeader::DEFAULT_ENCRYPTION_KEY_LENGTH);
	return derived_key;
}

std::array<uint8_t, EncryptionKeyManager::DERIVED_KEY_LENGTH> EncryptionKeyManager::DeriveKey(const string &user_key, data_ptr_t salt) {
	return KeyDerivationFunctionSHA256(user_key, salt);
}

string EncryptionKeyManager::ObjectType() {
	return "encryption_keys";
}

string EncryptionKeyManager::GetObjectType() {
	return ObjectType();
}

} // namespace duckdb

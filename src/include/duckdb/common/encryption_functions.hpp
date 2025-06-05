#pragma once

#include "duckdb/common/helper.hpp"
#include "duckdb/common/types/value.hpp"
#include "duckdb/common/encryption_state.hpp"
#include "duckdb/common/encryption_key_manager.hpp"

#ifndef DUCKDB_AMALGAMATION
#include "duckdb/storage/object_cache.hpp"
#endif

namespace duckdb {

class EncryptionEngine {

public:
	EncryptionEngine();
	~EncryptionEngine();

public:
	const uint8_t &GetKeyFromCache(DatabaseInstance &db) const;
	static const uint8_t &GetKeyFromCache(DatabaseInstance &db, const string &key_name);
	bool ContainsKey(DatabaseInstance &db, const string &key_name) const;
	static void AddKeyToCache(DatabaseInstance &db, string &key, const string &key_name, bool wipe = true);
	static string AddKeyToCache(DatabaseInstance &db, string &key);
	static void AddTempKeyToCache(DatabaseInstance &db);

	static void EncryptTemporaryBuffer(DatabaseInstance &db, FileBuffer &input_buffer, FileBuffer &out_buffer,
	                                   uint8_t *metadata);
	static void EncryptTemporaryBuffer(DatabaseInstance &db, FileBuffer &input_buffer, uint8_t *metadata);

	static void EncryptTemporaryAllocatedData(DatabaseInstance &db, AllocatedData &input_buffer,
	                                          AllocatedData &out_buffer, idx_t nr_bytes);
	static void EncryptTemporaryAllocatedData(DatabaseInstance &db, AllocatedData &input_buffer,
	                                          AllocatedData &out_buffer, idx_t nr_bytes, uint8_t *metadata);

	static void DecryptTemporaryBuffer(DatabaseInstance &db, const FileBuffer &input_buffer, uint8_t *metadata);
	static void DecryptTemporaryAllocatedData(DatabaseInstance &db, AllocatedData &input_buffer,
	                                          AllocatedData &out_buffer, idx_t nr_bytes);
	static void DecryptTemporaryAllocatedData(DatabaseInstance &db, AllocatedData &input_buffer, idx_t nr_bytes,
	                                          uint8_t *metadata);

private:
	void EncryptInternal();
	void EncryptBufferGCM();
	void EncryptBufferCTR();
	void EncryptBufferCBC();
};

class EncryptionTypes {

public:
	enum CipherType : uint8_t { UNKNOWN = 0, GCM = 1, CTR = 2, CBC = 3 };

	string CipherToString(CipherType cipher_p) const {
		switch (cipher_p) {
		case GCM:
			return "gcm";
		case CTR:
			return "ctr";
		case CBC:
			return "cbc";
		default:
			return "unknown";
		}
	}

	static CipherType StringToCipher(const string &encryption_cipher) {
		if (encryption_cipher == "gcm") {
			return CipherType::GCM;
		} else if (encryption_cipher == "ctr") {
			return CipherType::CTR;
		} else if (encryption_cipher == "cbc") {
			return CipherType::CBC;
		}
		return CipherType::UNKNOWN;
	}
};

} // namespace duckdb

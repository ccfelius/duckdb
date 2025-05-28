#pragma once

#include "duckdb/common/helper.hpp"
#include "duckdb/common/types/value.hpp"
#include "duckdb/common/encryption_state.hpp"

#ifndef DUCKDB_AMALGAMATION
#include "duckdb/storage/object_cache.hpp"
#endif

namespace duckdb {

class EncryptionEngine {

public:
	EncryptionEngine();
	~EncryptionEngine();

public:
	const string &GetKeyFromCache(DatabaseInstance &db) const;
	static const string &GetKeyFromCache(DatabaseInstance &db, const string &key_name);

	static void EncryptTemporaryBuffer(DatabaseInstance &db, FileBuffer &input_buffer, FileBuffer &out_buffer,
	                                   uint64_t delta, const string &key_name);
	static void DecryptTemporaryBuffer(DatabaseInstance &db, FileBuffer &input_buffer, FileBuffer &out_buffer,
	                                   uint64_t delta, const string &key_name);

private:
	void EncryptInternal();
	void EncryptBufferGCM();
	void EncryptBufferCTR();
	void EncryptBufferCBC();

private:
	EncryptionKeyManager key_manager;
	shared_ptr<EncryptionUtil> encryption_util;
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
};

} // namespace duckdb

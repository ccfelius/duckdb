#include "duckdb/common/encryption_key_manager.hpp"
#include "duckdb/common/encryption_functions.hpp"
#include "duckdb/main/attached_database.hpp"
#include "mbedtls_wrapper.hpp"

namespace duckdb {

EncryptionEngine::EncryptionEngine() {
}

const string &EncryptionEngine::GetKeyFromCache(DatabaseInstance &db, const string &key_name) {
	auto &keys = EncryptionKeyManager::Get(db);
	return keys.GetKey(key_name);
}

bool EncryptionEngine::ContainsKey(DatabaseInstance &db, const string &key_name) const {
	auto &keys = EncryptionKeyManager::Get(db);
	return keys.HasKey(key_name);
}

void EncryptionEngine::AddKeyToCache(DatabaseInstance &db, string &key, const string &key_name, bool wipe) {
	auto &keys = EncryptionKeyManager::Get(db);
	if (!keys.HasKey(key_name)) {
		keys.AddKey(key_name, key, wipe);
	} else if (wipe) {
		// wipe out the original key
		std::memset(&key[0], 0, key.size());
		key.clear();
	}
}

string EncryptionEngine::AddKeyToCache(DatabaseInstance &db, string &key) {
	auto &keys = EncryptionKeyManager::Get(db);
	auto key_id = keys.GenerateRandomKeyID();

	if (!keys.HasKey(key_id)) {
		keys.AddKey(key_id, key, true);
	} else {
		// wipe out the original key
		std::memset(&key[0], 0, key.size());
		key.clear();
	}

	return key_id;
}

void EncryptionEngine::AddTempKeyToCache(DatabaseInstance &db) {
	//! Add a temporary key to the cache
	auto temp_key = EncryptionKeyManager::GenerateRandomKey();
	string key_id = "temp_key";
	AddKeyToCache(db, temp_key, key_id);
}

void EncryptionEngine::EncryptTemporaryBuffer(DatabaseInstance &db, FileBuffer &input_buffer, FileBuffer &out_buffer,
                                              uint8_t *metadata) {

	auto temp_key = &GetKeyFromCache(db, "temp_key");

	auto encryption_util = db.GetEncryptionUtil();
	auto encryption_state = encryption_util->CreateEncryptionState(temp_key);

	// zero-out the metadata buffer
	memset(metadata, 0, DEFAULT_ENCRYPTED_BUFFER_HEADER_SIZE);

	uint8_t tag[MainHeader::AES_TAG_LEN];
	memset(tag, 0, MainHeader::AES_TAG_LEN);

	//! a nonce is randomly generated for every block
	uint8_t nonce[MainHeader::AES_IV_LEN];
	memset(nonce, 0, MainHeader::AES_IV_LEN);

#ifdef DEBUG
	uint8_t fixed_nonce[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 0, 0};
	memcpy(nonce, fixed_nonce, MainHeader::AES_NONCE_LEN);
#else

	encryption_state->GenerateRandomData(static_cast<data_ptr_t>(nonce), MainHeader::AES_NONCE_LEN);
#endif

	//! store the nonce at the the start of metadata buffer
	memcpy(metadata, nonce, MainHeader::AES_NONCE_LEN);
	encryption_state->InitializeEncryption(static_cast<data_ptr_t>(nonce), MainHeader::AES_NONCE_LEN, temp_key);

	auto aes_res = encryption_state->Process(input_buffer.InternalBuffer(), input_buffer.AllocSize(),
	                                         out_buffer.InternalBuffer(), input_buffer.AllocSize());

	if (aes_res != input_buffer.AllocSize()) {
		throw IOException("Encryption failure: in- and output size differ");
	}

	//! Finalize and extract the tag
	encryption_state->Finalize(out_buffer.InternalBuffer(), 0, static_cast<data_ptr_t>(tag), MainHeader::AES_TAG_LEN);

	//! store the generated tag after consequetively the nonce
	memcpy(metadata + MainHeader::AES_NONCE_LEN, tag, MainHeader::AES_TAG_LEN);
	// check if tag is correctly stored
	D_ASSERT(memcmp(tag, metadata + 12, 16) == 0);
}

void EncryptionEngine::EncryptTemporaryBuffer(DatabaseInstance &db, FileBuffer &input_buffer, uint8_t *metadata) {
	auto temp_key = &GetKeyFromCache(db, "temp_key");

	auto encryption_util = db.GetEncryptionUtil();
	auto encryption_state = encryption_util->CreateEncryptionState(temp_key);

	// zero-out the metadata buffer
	memset(metadata, 0, DEFAULT_ENCRYPTED_BUFFER_HEADER_SIZE);

	uint8_t tag[MainHeader::AES_TAG_LEN];
	memset(tag, 0, MainHeader::AES_TAG_LEN);

	//! a nonce is randomly generated for every block
	uint8_t nonce[MainHeader::AES_IV_LEN];
	memset(nonce, 0, MainHeader::AES_IV_LEN);

#ifdef DEBUG
	uint8_t fixed_nonce[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 0, 0};
	memcpy(nonce, fixed_nonce, MainHeader::AES_NONCE_LEN);
#else

	encryption_state->GenerateRandomData(static_cast<data_ptr_t>(nonce), MainHeader::AES_NONCE_LEN);
#endif

	//! store the nonce at the the start of metadata buffer
	memcpy(metadata, nonce, MainHeader::AES_NONCE_LEN);
	encryption_state->InitializeEncryption(static_cast<data_ptr_t>(nonce), MainHeader::AES_NONCE_LEN, temp_key);

	auto aes_res = encryption_state->Process(input_buffer.InternalBuffer(), input_buffer.AllocSize(),
	                                         input_buffer.InternalBuffer(), input_buffer.AllocSize());

	if (aes_res != input_buffer.AllocSize()) {
		throw IOException("Encryption failure: in- and output size differ");
	}

	//! Finalize and extract the tag
	encryption_state->Finalize(input_buffer.InternalBuffer(), 0, static_cast<data_ptr_t>(tag), MainHeader::AES_TAG_LEN);

	//! store the generated tag after consequetively the nonce
	memcpy(metadata + MainHeader::AES_NONCE_LEN, tag, MainHeader::AES_TAG_LEN);

	// check if tag is correctly stored
	D_ASSERT(memcmp(tag, metadata + 12, 16) == 0);
}

void EncryptionEngine::EncryptTemporaryAllocatedData(DatabaseInstance &db, AllocatedData &input_buffer,
                                                     AllocatedData &out_buffer, idx_t nr_bytes, uint8_t *metadata) {

	// this already expects an empty ("header" of delta bytes).
	auto &temp_key = GetKeyFromCache(db, "temp_key");

	auto encryption_util = db.GetEncryptionUtil();
	auto encryption_state = encryption_util->CreateEncryptionState(&temp_key);

	// zero-out the metadata buffer
	memset(metadata, 0, DEFAULT_ENCRYPTED_BUFFER_HEADER_SIZE);

	uint8_t tag[MainHeader::AES_TAG_LEN];
	memset(tag, 0, MainHeader::AES_TAG_LEN);

	//! a nonce is randomly generated for every block
	uint8_t nonce[MainHeader::AES_IV_LEN];
	memset(nonce, 0, MainHeader::AES_IV_LEN);

#ifdef DEBUG
	uint8_t fixed_nonce[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 0, 0};
	memcpy(nonce, fixed_nonce, MainHeader::AES_NONCE_LEN);
#else

	encryption_state->GenerateRandomData(static_cast<data_ptr_t>(nonce), MainHeader::AES_NONCE_LEN);
#endif

	//! store the nonce at the the start of metadata buffer
	memcpy(metadata, nonce, MainHeader::AES_NONCE_LEN);
	encryption_state->InitializeEncryption(static_cast<data_ptr_t>(nonce), MainHeader::AES_NONCE_LEN, &temp_key);

	// for compressed data, there is already made some space in the header during the compression
	auto aes_res = encryption_state->Process(input_buffer.get(), nr_bytes, out_buffer.get(), nr_bytes);

	if (aes_res != nr_bytes) {
		throw IOException("Encryption failure: in- and output size differ");
	}

	//! Finalize and extract the tag
	encryption_state->Finalize(out_buffer.get(), 0, static_cast<data_ptr_t>(tag), MainHeader::AES_TAG_LEN);
	//! store the generated tag after consequetively the nonce
	memcpy(metadata + MainHeader::AES_NONCE_LEN, tag, MainHeader::AES_TAG_LEN);
}

void EncryptionEngine::EncryptTemporaryAllocatedData(DatabaseInstance &db, AllocatedData &input_buffer,
                                                     AllocatedData &out_buffer, idx_t nr_bytes) {

	// this already expects an empty ("header" of delta bytes).
	auto &temp_key = GetKeyFromCache(db, "temp_key");

	auto encryption_util = db.GetEncryptionUtil();
	auto encryption_state = encryption_util->CreateEncryptionState(&temp_key);

	uint8_t tag[MainHeader::AES_TAG_LEN];
	memset(tag, 0, MainHeader::AES_TAG_LEN);

	//! a nonce is randomly generated for every block
	uint8_t nonce[MainHeader::AES_IV_LEN];
	memset(nonce, 0, MainHeader::AES_IV_LEN);

#ifdef DEBUG
	uint8_t fixed_nonce[12] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
	memcpy(nonce, fixed_nonce, MainHeader::AES_NONCE_LEN);
#else
	encryption_state->GenerateRandomData(static_cast<data_ptr_t>(nonce), MainHeader::AES_NONCE_LEN);
#endif

	//! store the nonce at the start of the block
	memcpy(out_buffer.get(), nonce, MainHeader::AES_NONCE_LEN);
	encryption_state->InitializeEncryption(static_cast<data_ptr_t>(nonce), MainHeader::AES_NONCE_LEN, &temp_key);
	auto out_buf_ptr = out_buffer.get();

	auto size = nr_bytes - DEFAULT_ENCRYPTED_BUFFER_HEADER_SIZE;

	// for compressed data, there is already made some space in the header during the compression
	auto aes_res = encryption_state->Process(input_buffer.get() + DEFAULT_ENCRYPTED_BUFFER_HEADER_SIZE, size,
	                                         out_buf_ptr + DEFAULT_ENCRYPTED_BUFFER_HEADER_SIZE, size);

	if (aes_res != size) {
		throw IOException("Encryption failure: in- and output size differ");
	}

	//! Finalize and extract the tag
	encryption_state->Finalize(out_buf_ptr + DEFAULT_ENCRYPTED_BUFFER_HEADER_SIZE, 0, static_cast<data_ptr_t>(tag),
	                           MainHeader::AES_TAG_LEN);

	//! store the generated tag after consequetively the nonce
	memcpy(out_buffer.get() + MainHeader::AES_NONCE_LEN, tag, MainHeader::AES_TAG_LEN);
}

void EncryptionEngine::DecryptTemporaryBuffer(DatabaseInstance &db, const FileBuffer &input_buffer, uint8_t *metadata) {

	//! initialize encryption state
	auto encryption_util = db.GetEncryptionUtil();
	auto temp_key = &GetKeyFromCache(db, "temp_key");
	auto encryption_state = encryption_util->CreateEncryptionState(temp_key);

	//! load the stored nonce
	uint8_t nonce[MainHeader::AES_IV_LEN];
	memset(nonce, 0, MainHeader::AES_IV_LEN);
	memcpy(nonce, metadata, MainHeader::AES_NONCE_LEN);

	//! load the tag for verification
	uint8_t tag[MainHeader::AES_TAG_LEN];
	memset(tag, 0, MainHeader::AES_TAG_LEN);
	memcpy(tag, metadata + MainHeader::AES_NONCE_LEN, MainHeader::AES_TAG_LEN);

	//! Initialize the decryption
	encryption_state->InitializeDecryption(nonce, MainHeader::AES_NONCE_LEN, temp_key);

	auto aes_res = encryption_state->Process(input_buffer.InternalBuffer(), input_buffer.AllocSize(),
	                                         input_buffer.InternalBuffer(), input_buffer.AllocSize());

	if (aes_res != input_buffer.AllocSize()) {
		throw IOException("Encryption failure: in- and output size differ");
	}

	//! check the tag
	encryption_state->Finalize(input_buffer.InternalBuffer(), 0, static_cast<data_ptr_t>(tag), MainHeader::AES_TAG_LEN);
}

void EncryptionEngine::DecryptTemporaryAllocatedData(DatabaseInstance &db, AllocatedData &input_buffer,
                                                     AllocatedData &out_buffer, idx_t nr_bytes) {

	//! initialize encryption state
	auto encryption_util = db.GetEncryptionUtil();
	auto temp_key = &GetKeyFromCache(db, "temp_key");
	auto encryption_state = encryption_util->CreateEncryptionState(temp_key);

	//! load the stored nonce
	uint8_t nonce[MainHeader::AES_IV_LEN];
	memset(nonce, 0, MainHeader::AES_IV_LEN);
	memcpy(nonce, input_buffer.get(), MainHeader::AES_NONCE_LEN);

	//! load the tag for verification
	uint8_t tag[MainHeader::AES_TAG_LEN];
	memcpy(tag, input_buffer.get() + MainHeader::AES_NONCE_LEN, MainHeader::AES_TAG_LEN);

	//! Initialize the decryption
	encryption_state->InitializeDecryption(nonce, MainHeader::AES_NONCE_LEN, temp_key);

	// real buffer
	auto size = nr_bytes - DEFAULT_ENCRYPTED_BUFFER_HEADER_SIZE;
	data_ptr_t buf_ptr = input_buffer.get() + DEFAULT_ENCRYPTED_BUFFER_HEADER_SIZE;

	auto aes_res = encryption_state->Process(buf_ptr, size, out_buffer.get(), size);

	if (aes_res != size) {
		throw IOException("Encryption failure: in- and output size differ");
	}

	//! check the tag
	encryption_state->Finalize(buf_ptr, 0, static_cast<data_ptr_t>(tag), MainHeader::AES_TAG_LEN);
}

void EncryptionEngine::DecryptTemporaryAllocatedData(DatabaseInstance &db, AllocatedData &input_buffer, idx_t nr_bytes,
                                                     uint8_t *metadata) {

	//! initialize encryption state
	auto encryption_util = db.GetEncryptionUtil();
	auto temp_key = &GetKeyFromCache(db, "temp_key");
	auto encryption_state = encryption_util->CreateEncryptionState(temp_key);

	//! load the stored nonce
	uint8_t nonce[MainHeader::AES_IV_LEN];
	memset(nonce, 0, MainHeader::AES_IV_LEN);
	memcpy(nonce, metadata, MainHeader::AES_NONCE_LEN);

	//! load the tag for verification
	uint8_t tag[MainHeader::AES_TAG_LEN];
	memcpy(tag, metadata + MainHeader::AES_NONCE_LEN, MainHeader::AES_TAG_LEN);

	//! Initialize the decryption
	encryption_state->InitializeDecryption(nonce, MainHeader::AES_NONCE_LEN, temp_key);
	auto aes_res = encryption_state->Process(input_buffer.get(), nr_bytes, input_buffer.get(), nr_bytes);
	if (aes_res != nr_bytes) {
		throw IOException("Encryption failure: in- and output size differ");
	}
	//! check the tag
	encryption_state->Finalize(input_buffer.get(), 0, static_cast<data_ptr_t>(tag), MainHeader::AES_TAG_LEN);
}

} // namespace duckdb

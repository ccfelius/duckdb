#include "duckdb/common/encryption_key_manager.hpp"
#include "duckdb/common/encryption_functions.hpp"
#include "duckdb/main/attached_database.hpp"
#include "mbedtls_wrapper.hpp"

namespace duckdb {
EncryptionEngine::EncryptionEngine() {

};

const string &EncryptionEngine::GetKeyFromCache(DatabaseInstance &db, const string &key_name) {
	auto &keys = EncryptionKeyManager::Get(db);
	return keys.GetKey(key_name);
}

void EncryptionEngine::EncryptTemporaryBuffer(DatabaseInstance &db, FileBuffer &input_buffer, FileBuffer &out_buffer,
                                              const string &key_name) {
	data_ptr_t block_offset_internal = out_buffer.InternalBuffer();
	string fixed_key = "1234567890abcdef1234567890abcdef";

	auto encryption_util = db.GetEncryptionUtil();
	auto encryption_state = encryption_util->CreateEncryptionState(&fixed_key);

	uint8_t tag[MainHeader::AES_TAG_LEN];
	memset(tag, 0, MainHeader::AES_TAG_LEN);

	//! a nonce is randomly generated for every block
	uint8_t nonce[MainHeader::AES_IV_LEN];
	memset(nonce, 0, MainHeader::AES_IV_LEN);
	encryption_state->GenerateRandomData(static_cast<data_ptr_t>(nonce), MainHeader::AES_NONCE_LEN);

	//! store the nonce at the start of the block
	memcpy(block_offset_internal, nonce, MainHeader::AES_NONCE_LEN);
	encryption_state->InitializeEncryption(static_cast<data_ptr_t>(nonce), MainHeader::AES_NONCE_LEN, &fixed_key);

	auto encryption_checksum_offset = block_offset_internal + delta;
	auto size = input_buffer.size + Storage::DEFAULT_BLOCK_HEADER_SIZE;

	//! encrypt the data including the checksum
	auto aes_res = encryption_state->Process(checksum_offset, size, encryption_checksum_offset, size);

	if (aes_res != size) {
		throw IOException("Encryption failure: in- and output size differ");
	}

	//! Finalize and extract the tag
	encryption_state->Finalize(input_buffer.InternalBuffer() + delta, 0, static_cast<data_ptr_t>(tag),
	                           MainHeader::AES_TAG_LEN);

	//! store the generated tag after consequetively the nonce
	memcpy(block_offset_internal + MainHeader::AES_NONCE_LEN, tag, MainHeader::AES_TAG_LEN);
}

void EncryptionEngine::DecryptBuffer(DatabaseInstance &db, FileBuffer &input_buffer, FileBuffer &out_buffer,
                                     uint64_t delta, const string &key_name) {
	//! initialize encryption state
	auto encryption_util = db.GetEncryptionUtil();
	auto encryption_state = encryption_util->CreateEncryptionState(&GetKeyFromCache());

	//! load the stored nonce
	uint8_t nonce[MainHeader::AES_IV_LEN];
	memset(nonce, 0, MainHeader::AES_IV_LEN);
	memcpy(nonce, internal_buffer, MainHeader::AES_NONCE_LEN);

	//! load the tag for verification
	uint8_t tag[MainHeader::AES_TAG_LEN];
	memcpy(tag, internal_buffer + MainHeader::AES_NONCE_LEN, MainHeader::AES_TAG_LEN);

	//! Initialize the decryption
	encryption_state->InitializeDecryption(nonce, MainHeader::AES_NONCE_LEN, &GetKeyFromCache());

	auto checksum_offset = internal_buffer + delta;
	auto size = block_size + Storage::DEFAULT_BLOCK_HEADER_SIZE;

	//! decrypt the block including the checksum
	auto aes_res = encryption_state->Process(checksum_offset, size, checksum_offset, size);

	if (aes_res != block_size + Storage::DEFAULT_BLOCK_HEADER_SIZE) {
		throw IOException("Encryption failure: in- and output size differ");
	}

	//! check the tag
	aes_res =
	    encryption_state->Finalize(internal_buffer + delta, 0, static_cast<data_ptr_t>(tag), MainHeader::AES_TAG_LEN);
}
}
}

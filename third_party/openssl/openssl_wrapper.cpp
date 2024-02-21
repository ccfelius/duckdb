#define TEST_KEY "01234567891123450123456789112345" // 256
// #define TEST_KEY "012345678911234501234567" // 196
// #define TEST_KEY "0123456789112345" //

#include "include/openssl_wrapper.hpp"
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <iostream>
#include "duckdb/common/common.hpp"

using namespace duckdb;
using namespace duckdb_openssl;

openSSLWrapper::AESGCMStateSSL::AESGCMStateSSL(const std::string &key) : gcm_context(EVP_CIPHER_CTX_new()) {

	// Create and initialize the context
	gcm_context = EVP_CIPHER_CTX_new();

	if(!(gcm_context)) {
		throw InternalException("AES GCM failed with initializing context");
	}

	// TODO Set Key with AES GCM
	// do later, need to rewrite where to give the key or make seperate method?

//	auto context = reinterpret_cast<mbedtls_gcm_context *>(gcm_context);
//	mbedtls_gcm_init(context);
//	if (mbedtls_gcm_setkey(context, MBEDTLS_CIPHER_ID_AES, reinterpret_cast<const unsigned char *>(key.c_str()),
//	                       key.length() * 8) != 0) {
//		throw runtime_error("Invalid AES key length");
//	}
}

// destructor
openSSLWrapper::AESGCMStateSSL::~AESGCMStateSSL() {
	/* Clean up */
	EVP_CIPHER_CTX_free(gcm_context);
//	delete gcm_context;
}

bool openSSLWrapper::AESGCMStateSSL::ValidKey(const std::string &key) {
	switch (key.size()) {
	case 16:
	case 24:
	case 32:
		return true;
	default:
		return false;
	}
}

void openSSLWrapper::AESGCMStateSSL::GenerateRandomData(duckdb::data_ptr_t data, duckdb::idx_t len) {
	// generate random bytes for nonce
	RAND_bytes(data, len);
}

const EVP_CIPHER* openSSLWrapper::AESGCMStateSSL::GetCipher(const std::string &key) {
	switch (key.size()) {
		case 16:
			cipher = EVP_aes_128_gcm();
			break;
		case 24:
			cipher = EVP_aes_192_gcm();
			break;
		case 32:
			cipher = EVP_aes_256_gcm();
			break;
		default:
			break;
		}

		return cipher;
	}

void openSSLWrapper::AESGCMStateSSL::InitializeEncryption(duckdb::const_data_ptr_t iv, duckdb::idx_t iv_len) {

	// set encryption mode
	mode = false;

	// Initialize the encryption operation
	if (1 != EVP_EncryptInit_ex(gcm_context, cipher, NULL, NULL, NULL)) {
		throw InternalException("AES GCM failed with initializing encrypt operation");
	}

     // Set IV length (default is 12 bytes)
	if(1 != EVP_CIPHER_CTX_ctrl(gcm_context, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) {
		throw InternalException("AES GCM failed with setting the iv length");
	}

	// Initialise key and IV
	if(1 != EVP_EncryptInit_ex(gcm_context, NULL, NULL, (const unsigned char*) TEST_KEY, iv)) {
		throw InternalException("AES GCM failed with initializing key and IV");
	}
}

// TODO; Key is hardcoded, rewrite for PR
void openSSLWrapper::AESGCMStateSSL::InitializeDecryption(duckdb::const_data_ptr_t iv, duckdb::idx_t iv_len) {

	// set mode to 1 to indicate decryption
	mode = true;

	// Initialise the decryption operation.
	if(!EVP_DecryptInit_ex(gcm_context, cipher, NULL, NULL, NULL)) {
		throw InternalException("AES GCM failed");
	}

	// Set IV length. default is 12 bytes (96 bits)
	if(!EVP_CIPHER_CTX_ctrl(gcm_context, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) {
		throw InternalException("AES GCM failed");
	}

	// Initialise key and IV
	if(!EVP_DecryptInit_ex(gcm_context, NULL, NULL, (const unsigned char*) TEST_KEY, iv)) {
		throw InternalException("AES GCM failed");
	}
}

size_t openSSLWrapper::AESGCMStateSSL::Process(duckdb::const_data_ptr_t in, duckdb::idx_t in_len, duckdb::data_ptr_t out,
                                            duckdb::idx_t out_len) {

	if (!mode) {
		// TODO: Add AAD data
//		if (1 != EVP_EncryptUpdate(gcm_context, NULL, (int *)&out_len, (unsigned char *)"", 0)) {
//			throw InternalException("AES GCM failed with encrypt update aad");
//		}

		if (1 != EVP_EncryptUpdate(gcm_context, (unsigned char *)(out), (int *)&out_len, (const unsigned char *)in,
		                           (int)in_len)) {
			throw InternalException("AES GCM failed with encrypt update gcm");
		}

	} else {
		// TODO: Add AAD data
//		if (1 != EVP_DecryptUpdate(gcm_context, NULL, (int *)&out_len, (unsigned char *)"", 0)) {
//			throw InternalException("AES GCM failed with decrypt update of setting AAD");
//		}

		if (1 != EVP_DecryptUpdate(gcm_context, (unsigned char *)(out), (int *)&out_len, (const unsigned char *)in,
			                       (int)in_len)) {
			throw InternalException("AES GCM failed with decrypt update");
		}
	}

	if (out_len != in_len) {
		throw InternalException("AES GCM failed, in and out lengths differ");
	}

	return out_len;

}

size_t openSSLWrapper::AESGCMStateSSL::Finalize(duckdb::data_ptr_t out, duckdb::idx_t out_len, duckdb::data_ptr_t tag,
                                             duckdb::idx_t tag_len) {

	auto text_len = out_len;

	if (!mode) {
		// Encrypt. Normally ciphertext bytes may be written at
		// this stage, but this does not occur in GCM mode
		if (1 != EVP_EncryptFinal_ex(gcm_context, (unsigned char *)(out) + out_len, (int *)&out_len)) {
			throw InternalException("AES GCM failed, with finalizing encryption");
		}

		text_len += out_len;

		// The generated tag is written at the end of a chunk
		if (1 != EVP_CIPHER_CTX_ctrl(gcm_context, EVP_CTRL_GCM_GET_TAG, tag_len, tag)) {
			throw InternalException("AES GCM failed, with getting tag");
		}

		return text_len;

	}

	else {
		// Finalize Decryption
		// Set expected tag value. Works in OpenSSL 1.0.1d and later
		if(!EVP_CIPHER_CTX_ctrl(gcm_context, EVP_CTRL_GCM_SET_TAG, tag_len, tag)) {
			throw InternalException("AES GCM failed, finalizing tag value");
		}

		// EVP_DecryptFinal() will return an error code if padding is enabled and the final block is not correctly formatted.
		int ret = EVP_DecryptFinal_ex(gcm_context, (unsigned char *)(out) + out_len, (int *)&out_len);
		text_len += out_len;

		if(ret > 0) {
			// success
			return text_len;

		} else {
			// Verify failed
			throw InternalException("Verification of Decrypted text failed. Are you using the right key or file?");
			return -1;
		}
	}
}
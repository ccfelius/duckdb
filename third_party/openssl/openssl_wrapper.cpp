//#define TEST_KEY "01234567891123450123456789112345" // 256
// #define TEST_KEY "012345678911234501234567" // 196
 #define TEST_KEY "0123456789112345" // 128

#include "include/openssl_wrapper.hpp"
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <iostream>
#include "duckdb/common/common.hpp"

using namespace duckdb;
using namespace duckdb_openssl;

openSSLWrapper::AESGCMStateSSL::AESGCMStateSSL(const std::string &key) : context(EVP_CIPHER_CTX_new()) {

	// Create and initialize the context
	context = EVP_CIPHER_CTX_new();

	if(!(context)) {
		throw InternalException("AES GCM failed with initializing context");
	}

	// TODO Set Key with AES GCM
	// do later, need to rewrite where to give the key or make seperate method?

//	auto context = reinterpret_cast<mbedtls_context *>(context);
//	mbedtls_gcm_init(context);
//	if (mbedtls_gcm_setkey(context, MBEDTLS_CIPHER_ID_AES, reinterpret_cast<const unsigned char *>(key.c_str()),
//	                       key.length() * 8) != 0) {
//		throw runtime_error("Invalid AES key length");
//	}
}

// destructor
openSSLWrapper::AESGCMStateSSL::~AESGCMStateSSL() {
	/* Clean up */
	EVP_CIPHER_CTX_free(context);
//	delete context;
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

// for now make it a bool
// refactor this to AES mode
// create an enum
void openSSLWrapper::AESGCMStateSSL::SetModeAES(bool &aes_mode) {
	// true = gcm, false = ctr
	gcm = aes_mode;
}

bool openSSLWrapper::AESGCMStateSSL::GetModeAES() {
	// true = gcm, false = ctr
	return gcm;
}

const EVP_CIPHER* openSSLWrapper::AESGCMStateSSL::GetCipher(const std::string &key) {

	if (!gcm) {
		switch (key.size()) {
		case 16:
			return EVP_aes_128_ctr();
		case 24:
			return EVP_aes_192_ctr();
		case 32:
			return EVP_aes_256_ctr();
		default:
			throw InternalException("Wrong Key Size");
		}
	}

	switch (key.size()) {
		case 16:
			return EVP_aes_128_gcm();
		case 24:
			return EVP_aes_192_gcm();
		case 32:
			return EVP_aes_256_gcm();
		default:
			throw InternalException("Wrong Key Size");
		}
	}

void openSSLWrapper::AESGCMStateSSL::InitializeEncryption(duckdb::const_data_ptr_t iv, duckdb::idx_t iv_len) {

	// set encryption mode
	mode = false;

	if(1 != EVP_EncryptInit_ex(context, cipher, NULL, (const unsigned char *)TEST_KEY, iv)) {
		    throw InternalException("AES CTR failed with EncryptInit");
	}

}

// TODO; Key is hardcoded, rewrite for PR
void openSSLWrapper::AESGCMStateSSL::InitializeDecryption(duckdb::const_data_ptr_t iv, duckdb::idx_t iv_len) {

	// set mode to 1 to indicate decryption
	mode = true;

	if(1 != EVP_DecryptInit_ex(context, cipher, NULL, (const unsigned char *)TEST_KEY, iv)) {
		    throw std::runtime_error("EVP_EncryptInit_ex failed");
	}

}

size_t openSSLWrapper::AESGCMStateSSL::Process(duckdb::const_data_ptr_t in, duckdb::idx_t in_len, duckdb::data_ptr_t out,
                                            duckdb::idx_t out_len) {

	if (!mode) {

		if (1 != EVP_EncryptUpdate(context, (unsigned char *)(out), (int *)&out_len, (const unsigned char *)in,
		                           (int)in_len)) {
			throw InternalException("AES GCM failed with encrypt update gcm");
		}

	} else {

		if (1 != EVP_DecryptUpdate(context, (unsigned char *)(out), (int *)&out_len, (const unsigned char *)in,
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

		// Encrypt
		if (1 != EVP_EncryptFinal_ex(context, (unsigned char *)(out) + out_len, (int *)&out_len)) {
			throw InternalException("AES GCM failed, with finalizing encryption");
		}

		text_len += out_len;

		if (gcm) {
			// The generated tag is written at the end of a chunk in GCM mode
			if (1 != EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_GET_TAG, tag_len, tag)) {
				throw InternalException("AES GCM failed, with getting tag");
			}
		}

		return text_len;

	}

	else {
		// Finalize Decryption

		if (gcm) {
			// Set expected tag value
			if (!EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_TAG, tag_len, tag)) {
				throw InternalException("AES GCM failed, finalizing tag value");
			}
		}

		// EVP_DecryptFinal() will return an error code if padding is enabled and the final block is not correctly formatted.
		int ret = EVP_DecryptFinal_ex(context, (unsigned char *)(out) + out_len, (int *)&out_len);

		text_len += out_len;

		if (ret > 0) {
			// success
			return text_len;

		} else {
			// Verify failed
			throw InternalException("Verification of Decrypted text failed. Are you using the right key or file?");
			return -1;
		}
	}
}
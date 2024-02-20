#define TEST_KEY "01234567891123450123456789112345"
// #define TEST_KEY "012345678911234501234567"
// #define TEST_KEY "0123456789112345"

#include "include/openssl_wrapper.hpp"
#include <openssl/evp.h>
#include <openssl/aes.h>
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

void openSSLWrapper::AESGCMStateSSL::InitializeEncryption(duckdb::const_data_ptr_t iv, duckdb::idx_t iv_len) {

	// set encryption mode
	mode = false;

	// Initialize the encryption operation
	if (1 != EVP_EncryptInit_ex(gcm_context, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
		throw InternalException("AES GCM failed with initializing encrypt operation");
	}

     // Set IV length if default 12 bytes (96 bits) is not appropriate
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
	if(!EVP_DecryptInit_ex(gcm_context, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
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

		if (1 != EVP_EncryptUpdate(gcm_context, NULL, (int *)&out_len, (unsigned char *)"", 0)) {
			throw InternalException("AES GCM failed with encrypt update aad");
		}

		if (1 != EVP_EncryptUpdate(gcm_context, (unsigned char *)(out), (int *)&out_len, (const unsigned char *)in,
		                           (int)in_len)) {
			throw InternalException("AES GCM failed with encrypt update gcm");
		}

	} else {

		if (1 != EVP_DecryptUpdate(gcm_context, NULL, (int *)&out_len, (unsigned char *)"", 0)) {
			throw InternalException("AES GCM failed with decrypt update of setting AAD");
		}

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

	int text_len = out_len;

	if (!mode) {

		// Encrypt. Normally ciphertext bytes may be written at
		// this stage, but this does not occur in GCM mode
		if (1 != EVP_EncryptFinal_ex(gcm_context, (unsigned char *)(out) + out_len, (int *)&out_len)) {
			throw InternalException("AES GCM failed, with finalizing encryption");
		}
		text_len += out_len;

		// Get the tag
		if (1 != EVP_CIPHER_CTX_ctrl(gcm_context, EVP_CTRL_GCM_GET_TAG, tag_len, tag)) {
			throw InternalException("AES GCM failed, with getting tag");
		}

		return text_len;

	}

	else {
		// Decrypt
		// Set expected tag value. Works in OpenSSL 1.0.1d and later
		if(!EVP_CIPHER_CTX_ctrl(gcm_context, EVP_CTRL_GCM_SET_TAG, tag_len, tag)) {
			throw InternalException("AES GCM failed, finalizing tag value");
		}

		int ret = EVP_DecryptFinal_ex(gcm_context, (unsigned char *)(out) + out_len, (int *)&out_len);
		text_len += out_len;

		if(ret > 0) {
			// success
			return text_len;

		} else {
			// Verify failed
			throw InternalException("Verification of Decrypted text failed with a length of: %d", out_len);
			return -1;
		}
	}

}

int openSSLWrapper::AESGCMStateSSL::gcm_encrypt(unsigned char *plaintext, int plaintext_len,
                unsigned char *aad, int aad_len,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *ciphertext,
                unsigned char *tag)
{
	EVP_CIPHER_CTX *ctx;

	int len;
	int ciphertext_len;

	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new()))
		throw std::runtime_error("AES GCM failed");

	/* Initialise the encryption operation. */
	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
		throw std::runtime_error("AES GCM failed");

	/*
     * Set IV length if default 12 bytes (96 bits) is not appropriate
	 */

	if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
		throw std::runtime_error("AES GCM failed");

	/* Initialise key and IV */
	if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
		throw std::runtime_error("AES GCM failed");

	/*
     * Provide any AAD data. This can be called zero or more times as
     * required
	 */

	if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
		throw std::runtime_error("AES GCM failed");

	/*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
	 */

	if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
		throw std::runtime_error("AES GCM failed");

	ciphertext_len = len;

	/*
     * Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
	 */

	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
		throw std::runtime_error("AES GCM failed");
	ciphertext_len += len;

	/* Get the tag */
	if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
		throw std::runtime_error("AES GCM failed");

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}

int openSSLWrapper::AESGCMStateSSL::gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                                                 unsigned char *aad, int aad_len,
                                                 unsigned char *tag,
                                                 unsigned char *key,
                                                 unsigned char *iv, int iv_len,
                                                 unsigned char *plaintext)
{
	EVP_CIPHER_CTX *ctx;

	int len;
	int plaintext_len;
	int ret;

	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new()))
		throw std::runtime_error("AES GCM failed");

	/* Initialise the decryption operation. */
	if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
		throw std::runtime_error("AES GCM failed");

	/* Set IV length. Not necessary if this is 12 bytes (96 bits) */
	if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
		throw std::runtime_error("AES GCM failed");

	/* Initialise key and IV */
	if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
		throw std::runtime_error("AES GCM failed");

	/*
     * Provide any AAD data. This can be called zero or more times as
     * required
	 */
	if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
		throw std::runtime_error("AES GCM failed");

	/*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
	 */

	if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
		throw std::runtime_error("AES GCM failed");
	plaintext_len = len;

	/* Set expected tag value. Works in OpenSSL 1.0.1d and later */
	if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
		throw std::runtime_error("AES GCM failed");

	/*
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
	 */

	ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	if(ret > 0) {
		/* Success */
		plaintext_len += len;
		return plaintext_len;

	} else {
		/* Verify failed */
		return -1;
	}
}
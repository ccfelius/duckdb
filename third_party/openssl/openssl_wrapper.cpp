//
// Created by Lotte Felius on 16/02/2024.
//

#define NONCE_BYTES 28 // For OPENSSL AES GCM
#define TEST_KEY "0123456789012345678901234567890"
#define TEST_NONCE "012345678901234567890"

#include "include/openssl_wrapper.hpp"
#include <openssl/evp.h>
#include <openssl/aes.h>

using namespace std;
using namespace duckdb_openssl;

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
	mode = 0;
	int len;
	int ciphertext_len;

	/* Create and initialise the context */
	if(!(gcm_context = EVP_CIPHER_CTX_new()))
		throw std::runtime_error("AES GCM failed");

	/* Initialise the encryption operation. */
	if (1 != EVP_EncryptInit_ex(gcm_context, EVP_aes_256_gcm(), NULL, NULL, NULL))
		throw std::runtime_error("AES GCM failed");

	/*
     * Set IV length if default 12 bytes (96 bits) is not appropriate
	 */

	if(1 != EVP_CIPHER_CTX_ctrl(gcm_context, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
		throw std::runtime_error("AES GCM failed");

	/* Initialise key and IV */
	if(1 != EVP_EncryptInit_ex(gcm_context, NULL, NULL, (const unsigned char*) TEST_KEY, iv))
		throw std::runtime_error("AES GCM failed");

}

void openSSLWrapper::AESGCMStateSSL::InitializeDecryption(duckdb::const_data_ptr_t iv, duckdb::idx_t iv_len) {

	// set mode to 1 to indicate decryption
	mode = 1;
	// TODO:
//	auto context = reinterpret_cast<openSSL_gcm_context *>(gcm_context);
//	if (openSSL_gcm_starts(context, openssl_GCM_DECRYPT, iv, iv_len) != 0) {
//		throw runtime_error("Unable to initialize AES decryption");
//	}

	int len;
	int plaintext_len;
	int ret;

	/* Create and initialise the context */
	if(!(gcm_context = EVP_CIPHER_CTX_new()))
		throw std::runtime_error("AES GCM failed");

	/* Initialise the decryption operation. */
	if(!EVP_DecryptInit_ex(gcm_context, EVP_aes_256_gcm(), NULL, NULL, NULL))
		throw std::runtime_error("AES GCM failed");

	/* Set IV length. Not necessary if this is 12 bytes (96 bits) */
	if(!EVP_CIPHER_CTX_ctrl(gcm_context, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
		throw std::runtime_error("AES GCM failed");

	/* Initialise key and IV */
	if(!EVP_DecryptInit_ex(gcm_context, NULL, NULL, (const unsigned char*) TEST_KEY, iv))
		throw std::runtime_error("AES GCM failed");

}

// need to change the types to unsigned char

size_t openSSLWrapper::AESGCMStateSSL::Process(duckdb::const_data_ptr_t in, duckdb::idx_t in_len, duckdb::data_ptr_t out,
                                            duckdb::idx_t out_len) {

	if (!mode) {

	if (1 != EVP_EncryptUpdate(gcm_context, NULL, (int *)&out_len, (unsigned char *)"", 0)) {
		throw std::runtime_error("AES GCM failed");
	}

	if (1 !=
	    EVP_EncryptUpdate(gcm_context, (unsigned char *)(out), (int *)&out_len, (const unsigned char *)in, (int)in_len)){
		throw std::runtime_error("AES GCM failed");
}

	else {

}
		if (1 != EVP_DecryptUpdate(gcm_context, NULL, (int *)&out_len, (unsigned char *)"", 0)) {
			throw std::runtime_error("AES GCM failed");
		}

		if (1 != EVP_DecryptUpdate(gcm_context, (unsigned char *)(out), (int *)&out_len, (const unsigned char *)in,
			                       (int)in_len)) {
			throw std::runtime_error("AES GCM failed");
		}
	}

	if (out_len != in_len)
		throw std::runtime_error("AES GCM failed");

	return out_len;
//	ciphertext_len = len;
//	return result;
}


size_t openSSLWrapper::AESGCMStateSSL::Finalize(duckdb::data_ptr_t out, duckdb::idx_t out_len, duckdb::data_ptr_t tag,
                                             duckdb::idx_t tag_len) {

	/*
     * Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
	 */

	if (!mode) {

		if (1 != EVP_EncryptFinal_ex(gcm_context, (unsigned char *)(out), (int *)&out_len)) {
			throw std::runtime_error("AES GCM failed");
		}

		/* Get the tag */
		if (1 != EVP_CIPHER_CTX_ctrl(gcm_context, EVP_CTRL_GCM_GET_TAG, tag_len, tag))
			throw std::runtime_error("AES GCM failed");
	}

	// difference between out and outm in params?
	else {

		if (1 != EVP_DecryptFinal_ex(gcm_context, (unsigned char *)(out), (int *)&out_len)) {
			throw std::runtime_error("AES GCM failed");
		}

		/* Set expected tag value. Works in OpenSSL 1.0.1d and later */
		if(!EVP_CIPHER_CTX_ctrl(gcm_context, EVP_CTRL_GCM_SET_TAG, tag_len, tag))
			throw std::runtime_error("AES GCM failed");

//		__owur int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm,
//		                               int *outl);

		int ret = EVP_DecryptFinal_ex(gcm_context, (unsigned char *)(out), (int *)&out_len);

		if(ret > 0) {
			/* Success */
			return out_len;

		} else {
			/* Verify failed */
			return -1;
		}
	}

	// return ciphertext length
	return out_len + tag_len;

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
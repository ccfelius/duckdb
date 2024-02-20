//
// Created by Lotte Felius on 16/02/2024.
//

#ifndef DUCKDB_OPENSSL_WRAPPER_H
#define DUCKDB_OPENSSL_WRAPPER_H

#endif // DUCKDB_OPENSSL_WRAPPER_H

#include "duckdb/common/optional_ptr.hpp"
#include "duckdb/common/typedefs.hpp"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#include <string>

namespace duckdb_openssl {

class openSSLWrapper {
public:

	class AESGCMStateSSL {

	public:
		DUCKDB_API AESGCMStateSSL(const std::string &key);
		DUCKDB_API ~AESGCMStateSSL();

	public:
		DUCKDB_API static bool ValidKey(const std::string &key);
		DUCKDB_API void InitializeEncryption(duckdb::const_data_ptr_t iv, duckdb::idx_t iv_len);
		DUCKDB_API void InitializeDecryption(duckdb::const_data_ptr_t iv, duckdb::idx_t iv_len);
		DUCKDB_API size_t Process(duckdb::const_data_ptr_t in, duckdb::idx_t in_len, duckdb::data_ptr_t out,
		                          duckdb::idx_t out_len);
		DUCKDB_API size_t Finalize(duckdb::data_ptr_t out, duckdb::idx_t out_len, duckdb::data_ptr_t tag, duckdb::idx_t tag_len);
	public:
		static constexpr size_t BLOCK_SIZE = 16;
		int gcm_encrypt(unsigned char *plaintext, int plaintext_len,
		            unsigned char *aad, int aad_len,
		            unsigned char *key,
		            unsigned char *iv, int iv_len,
		            unsigned char *ciphertext,
		            unsigned char *tag);
		int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
		            unsigned char *aad, int aad_len,
		            unsigned char *tag,
		            unsigned char *key,
		            unsigned char *iv, int iv_len,
		            unsigned char *plaintext);
	private:
		evp_cipher_ctx_st *gcm_context;
		// 0 = encrypt, 1 = decrypt
		bool mode;
	};
};

} // namespace duckdb_openssl


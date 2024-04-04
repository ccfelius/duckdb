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
		DUCKDB_API const EVP_CIPHER* GetCipher(const std::string &key);
		DUCKDB_API static bool ValidKey(const std::string &key);
		DUCKDB_API void SetModeAES(bool &aes_mode);
		DUCKDB_API bool GetModeAES();
		DUCKDB_API void InitializeEncryption(duckdb::const_data_ptr_t iv, duckdb::idx_t iv_len);
		DUCKDB_API void InitializeDecryption(duckdb::const_data_ptr_t iv, duckdb::idx_t iv_len);
		DUCKDB_API size_t Process(duckdb::const_data_ptr_t in, duckdb::idx_t in_len, duckdb::data_ptr_t out,
		                          duckdb::idx_t out_len);
		DUCKDB_API size_t Finalize(duckdb::data_ptr_t out, duckdb::idx_t out_len, duckdb::data_ptr_t tag, duckdb::idx_t tag_len);
		DUCKDB_API static void GenerateRandomData(duckdb::data_ptr_t data, duckdb::idx_t len);

	public:
		// AES encrypts blocks of 128 bits, i.e. 16 bytes
		static constexpr size_t BLOCK_SIZE = 16;

	private:
		evp_cipher_ctx_st *context;
		// 0 = encrypt, 1 = decrypt
		bool mode;
		// TODO: make cipher and bool gcm dynamic
		// set cipher (depends on key length, default = 256)
		const EVP_CIPHER* cipher = EVP_aes_128_ctr();
		// true = gcm, false = ctr
		bool gcm = false;
		// TODO: remember key for this session
		const std::string key;
	};
};

} // namespace duckdb_openssl


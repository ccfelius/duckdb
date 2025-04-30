#include "mbedtls_wrapper.hpp"

// otherwise we have different definitions for mbedtls_pk_context / mbedtls_sha256_context
#define MBEDTLS_ALLOW_PRIVATE_ACCESS

#include "duckdb/common/helper.hpp"
#include "mbedtls/md.h"
#include "mbedtls/pk.h"
#include "mbedtls/sha1.h"
#include "mbedtls/sha256.h"
#include "mbedtls/cipher.h"
#include "psa/crypto.h"
#include <cstdio>
#include <cstring>

#include "duckdb/common/random_engine.hpp"
#include "duckdb/common/types/timestamp.hpp"

#include <stdexcept>

#define SHA_256_HASH_SIZE 32

using namespace std;
using namespace duckdb_mbedtls;

/*
# Command line tricks to help here
# Create a new key
openssl genrsa -out private.pem 2048

# Export public key
openssl rsa -in private.pem -outform PEM -pubout -out public.pem

# Calculate digest and write to 'hash' file on command line
openssl dgst -binary -sha256 dummy > hash

# Calculate signature from hash
openssl pkeyutl -sign -in hash -inkey private.pem -pkeyopt digest:sha256 -out dummy.sign
*/

void MbedTlsWrapper::ComputeSha256Hash(const char *in, size_t in_len, char *out) {

	mbedtls_sha256_context sha_context;
	mbedtls_sha256_init(&sha_context);
	if (mbedtls_sha256_starts(&sha_context, false) ||
	    mbedtls_sha256_update(&sha_context, reinterpret_cast<const unsigned char *>(in), in_len) ||
	    mbedtls_sha256_finish(&sha_context, reinterpret_cast<unsigned char *>(out))) {
		throw runtime_error("SHA256 Error");
	}
	mbedtls_sha256_free(&sha_context);
}

string MbedTlsWrapper::ComputeSha256Hash(const string &file_content) {
	string hash;
	hash.resize(MbedTlsWrapper::SHA256_HASH_LENGTH_BYTES);
	ComputeSha256Hash(file_content.data(), file_content.size(), (char *)hash.data());
	return hash;
}

bool MbedTlsWrapper::IsValidSha256Signature(const std::string &pubkey, const std::string &signature,
                                            const std::string &sha256_hash) {

	if (signature.size() != 256 || sha256_hash.size() != 32) {
		throw std::runtime_error("Invalid input lengths, expected signature length 256, got " +
		                         to_string(signature.size()) + ", hash length 32, got " +
		                         to_string(sha256_hash.size()));
	}

	mbedtls_pk_context pk_context;
	mbedtls_pk_init(&pk_context);

	if (mbedtls_pk_parse_public_key(&pk_context, reinterpret_cast<const unsigned char *>(pubkey.c_str()),
	                                pubkey.size() + 1)) {
		throw runtime_error("RSA public key import error");
	}

	// actually verify
	bool valid = mbedtls_pk_verify(&pk_context, MBEDTLS_MD_SHA256,
	                               reinterpret_cast<const unsigned char *>(sha256_hash.data()), sha256_hash.size(),
	                               reinterpret_cast<const unsigned char *>(signature.data()), signature.length()) == 0;

	mbedtls_pk_free(&pk_context);
	return valid;
}

// used in s3fs
void MbedTlsWrapper::Hmac256(const char *key, size_t key_len, const char *message, size_t message_len, char *out) {
	mbedtls_md_context_t hmac_ctx;
	const mbedtls_md_info_t *md_type = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	if (!md_type) {
		throw runtime_error("failed to init hmac");
	}

	if (mbedtls_md_setup(&hmac_ctx, md_type, 1) ||
	    mbedtls_md_hmac_starts(&hmac_ctx, reinterpret_cast<const unsigned char *>(key), key_len) ||
	    mbedtls_md_hmac_update(&hmac_ctx, reinterpret_cast<const unsigned char *>(message), message_len) ||
	    mbedtls_md_hmac_finish(&hmac_ctx, reinterpret_cast<unsigned char *>(out))) {
		throw runtime_error("HMAC256 Error");
	}
	mbedtls_md_free(&hmac_ctx);
}

void MbedTlsWrapper::ToBase16(char *in, char *out, size_t len) {
	static char const HEX_CODES[] = "0123456789abcdef";
	size_t i, j;

	for (j = i = 0; i < len; i++) {
		int a = in[i];
		out[j++] = HEX_CODES[(a >> 4) & 0xf];
		out[j++] = HEX_CODES[a & 0xf];
	}
}

void MbedTlsWrapper::PBKDF2(string *user_key, const uint8_t *salt, uint8_t *derived_key) {
	uint32_t key_length = 32;
	size_t user_key_length = user_key->size();
	size_t salt_length = 16;

	psa_status_t status;

	// Initialize PSA Crypto
	status = psa_crypto_init();
	if (status != PSA_SUCCESS) {
		throw runtime_error("PSA crypto initialization failed\n");
	}

	// Setup the key derivation operation
	psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
	status = psa_key_derivation_setup(&op, PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_256));
	if (status != PSA_SUCCESS) {
		throw runtime_error("Failed to setup key derivation operation\n");
	}

	// Set the input password and salt for PBKDF2
	status = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_PASSWORD, reinterpret_cast<const uint8_t *>(user_key), user_key_length);
	if (status != PSA_SUCCESS) {
		throw runtime_error("Failed to set password input\n");
	}

	status = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT, salt, salt_length);
	if (status != PSA_SUCCESS) {
		throw runtime_error("Failed to set salt input\n");
	}

	uint32_t iterations = 10000;
	uint8_t iterations_buf[sizeof(uint32_t)];
	memcpy(iterations_buf, &iterations, sizeof(iterations_buf));

	// Set the iteration count for PBKDF2
	status = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_COST, iterations_buf, sizeof(iterations_buf));
	if (status != PSA_SUCCESS) {
		throw runtime_error("Failed to set iteration count\n");
	}

	// Perform the PBKDF2 operation
	status = psa_key_derivation_output_bytes(&op, derived_key, key_length);
	if (status != PSA_SUCCESS) {
		throw runtime_error("Key derivation failed\n");
	}

	// Cleanup the key derivation operation
	psa_key_derivation_abort(&op);
}

MbedTlsWrapper::SHA256State::SHA256State() : sha_context(new mbedtls_sha256_context()) {
	auto context = reinterpret_cast<mbedtls_sha256_context *>(sha_context);

	mbedtls_sha256_init(context);

	if (mbedtls_sha256_starts(context, false)) {
		throw std::runtime_error("SHA256 Error");
	}
}

MbedTlsWrapper::SHA256State::~SHA256State() {
	auto context = reinterpret_cast<mbedtls_sha256_context *>(sha_context);
	mbedtls_sha256_free(context);
	delete context;
}

void MbedTlsWrapper::SHA256State::AddString(const std::string &str) {
	auto context = reinterpret_cast<mbedtls_sha256_context *>(sha_context);
	if (mbedtls_sha256_update(context, (unsigned char *)str.data(), str.size())) {
		throw std::runtime_error("SHA256 Error");
	}
}

std::string MbedTlsWrapper::SHA256State::Finalize() {
	auto context = reinterpret_cast<mbedtls_sha256_context *>(sha_context);

	string hash;
	hash.resize(MbedTlsWrapper::SHA256_HASH_LENGTH_BYTES);

	if (mbedtls_sha256_finish(context, (unsigned char *)hash.data())) {
		throw std::runtime_error("SHA256 Error");
	}

	return hash;
}

void MbedTlsWrapper::SHA256State::FinishHex(char *out) {
	auto context = reinterpret_cast<mbedtls_sha256_context *>(sha_context);

	string hash;
	hash.resize(MbedTlsWrapper::SHA256_HASH_LENGTH_BYTES);

	if (mbedtls_sha256_finish(context, (unsigned char *)hash.data())) {
		throw std::runtime_error("SHA256 Error");
	}

	MbedTlsWrapper::ToBase16(const_cast<char *>(hash.c_str()), out, MbedTlsWrapper::SHA256_HASH_LENGTH_BYTES);
}

MbedTlsWrapper::SHA1State::SHA1State() : sha_context(new mbedtls_sha1_context()) {
	auto context = reinterpret_cast<mbedtls_sha1_context *>(sha_context);

	mbedtls_sha1_init(context);

	if (mbedtls_sha1_starts(context)) {
		throw std::runtime_error("SHA1 Error");
	}
}

MbedTlsWrapper::SHA1State::~SHA1State() {
	auto context = reinterpret_cast<mbedtls_sha1_context *>(sha_context);
	mbedtls_sha1_free(context);
	delete context;
}

void MbedTlsWrapper::SHA1State::AddString(const std::string &str) {
	auto context = reinterpret_cast<mbedtls_sha1_context *>(sha_context);
	if (mbedtls_sha1_update(context, (unsigned char *)str.data(), str.size())) {
		throw std::runtime_error("SHA1 Error");
	}
}

std::string MbedTlsWrapper::SHA1State::Finalize() {
	auto context = reinterpret_cast<mbedtls_sha1_context *>(sha_context);

	string hash;
	hash.resize(MbedTlsWrapper::SHA1_HASH_LENGTH_BYTES);

	if (mbedtls_sha1_finish(context, (unsigned char *)hash.data())) {
		throw std::runtime_error("SHA1 Error");
	}

	return hash;
}

void MbedTlsWrapper::SHA1State::FinishHex(char *out) {
	auto context = reinterpret_cast<mbedtls_sha1_context *>(sha_context);

	string hash;
	hash.resize(MbedTlsWrapper::SHA1_HASH_LENGTH_BYTES);

	if (mbedtls_sha1_finish(context, (unsigned char *)hash.data())) {
		throw std::runtime_error("SHA1 Error");
	}

	MbedTlsWrapper::ToBase16(const_cast<char *>(hash.c_str()), out, MbedTlsWrapper::SHA1_HASH_LENGTH_BYTES);
}

const mbedtls_cipher_info_t *MbedTlsWrapper::AESStateMBEDTLS::GetCipher(size_t key_len){

	switch(cipher){
		case GCM:
		    switch (key_len) {
		    case 16:
			    return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_GCM);
		    case 24:
			    return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_192_GCM);
		    case 32:
			    return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_GCM);
		    default:
			    throw runtime_error("Invalid AES key length");
		    }

		case CTR:
		    switch (key_len) {
		    case 16:
			    return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_CTR);
		    case 24:
			    return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_192_CTR);
		    case 32:
			    return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_CTR);
		    default:
			    throw runtime_error("Invalid AES key length");
		    }

		default:
			throw duckdb::InternalException("Invalid Encryption/Decryption Cipher: %d", static_cast<int>(cipher));
	}
}

MbedTlsWrapper::AESStateMBEDTLS::AESStateMBEDTLS(const std::string *key) : context(duckdb::make_uniq<mbedtls_cipher_context_t>()) {
	mbedtls_cipher_init(context.get());

	auto cipher_info = GetCipher(key->length());
	if (!cipher_info) {
		runtime_error("Failed to get Cipher");
	}

	if (mbedtls_cipher_setup(context.get(), cipher_info) != 0) {
		runtime_error("Failed to initialize cipher context");
	}
}

MbedTlsWrapper::AESStateMBEDTLS::~AESStateMBEDTLS() {
	if (context) {
		mbedtls_cipher_free(context.get());
	}
}

void MbedTlsWrapper::AESStateMBEDTLS::GenerateRandomData(duckdb::data_ptr_t data, duckdb::idx_t len) {
	duckdb::RandomEngine random_engine(duckdb::Timestamp::GetCurrentTimestamp().value);
	while (len != 0) {
		const auto random_integer = random_engine.NextRandomInteger();
		const auto next = duckdb::MinValue<duckdb::idx_t>(len, sizeof(random_integer));
		memcpy(data, duckdb::const_data_ptr_cast(&random_integer), next);
		data += next;
		len -= next;
	}
}

void MbedTlsWrapper::AESStateMBEDTLS::InitializeEncryption(duckdb::const_data_ptr_t iv, duckdb::idx_t iv_len, const std::string *key) {
	mode = ENCRYPT;

	if (mbedtls_cipher_setkey(context.get(), reinterpret_cast<const unsigned char *>(key->data()), key->length() * 8, MBEDTLS_ENCRYPT) != 0) {
		runtime_error("Failed to set AES key for encryption");
	}

	if (mbedtls_cipher_set_iv(context.get(), iv, iv_len) != 0) {
		runtime_error("Failed to set IV for encryption");
	}
}

void MbedTlsWrapper::AESStateMBEDTLS::InitializeDecryption(duckdb::const_data_ptr_t iv, duckdb::idx_t iv_len, const std::string *key) {
	mode = DECRYPT;

	if (mbedtls_cipher_setkey(context.get(), reinterpret_cast<const unsigned char *>(key->data()), key->length() * 8, MBEDTLS_DECRYPT) != 0) {
		runtime_error("Failed to set AES key for decryption");
	}

	if (mbedtls_cipher_set_iv(context.get(), iv, iv_len) != 0) {
		runtime_error("Failed to set IV for decryption");
	}
}

size_t MbedTlsWrapper::AESStateMBEDTLS::Process(duckdb::const_data_ptr_t in, duckdb::idx_t in_len, duckdb::data_ptr_t out,
                                                   duckdb::idx_t out_len) {
	size_t result;
	if (mbedtls_cipher_update(context.get(), reinterpret_cast<const unsigned char *>(in), in_len, out,
	                      &result) != 0) {
			runtime_error("Encryption or Decryption failed at Process");
		};

	return result;
}

void MbedTlsWrapper::AESStateMBEDTLS::FinalizeGCM(duckdb::data_ptr_t tag, duckdb::idx_t tag_len){

	switch (mode) {

	case ENCRYPT: {
		if (mbedtls_cipher_write_tag(context.get(), tag, tag_len) != 0) {
			runtime_error("Writing tag failed");
		}
		break;
	}

	case DECRYPT: {
		if (mbedtls_cipher_check_tag(context.get(), tag, tag_len) != 0) {
			throw duckdb::InvalidInputException(
			    "Computed AES tag differs from read AES tag, are you using the right key?");
		}
		break;
	}

	default:
		throw duckdb::InternalException("Unhandled encryption mode %d", static_cast<int>(mode));
	}
}

size_t MbedTlsWrapper::AESStateMBEDTLS::Finalize(duckdb::data_ptr_t out, duckdb::idx_t out_len, duckdb::data_ptr_t tag,
                                                    duckdb::idx_t tag_len) {
	size_t result = out_len;
	mbedtls_cipher_finish(context.get(), out, &result);
	FinalizeGCM(tag, tag_len);

	return result;
}

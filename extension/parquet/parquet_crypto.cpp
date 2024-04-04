#include "parquet_crypto.hpp"
#include "mbedtls_wrapper.hpp"
#include "openssl_wrapper.hpp"
#include "thrift_tools.hpp"

#ifndef DUCKDB_AMALGAMATION
#include "duckdb/common/common.hpp"
#include "duckdb/storage/arena_allocator.hpp"
#endif

#ifndef OPENSSL_FOUND
#include
#endif


namespace duckdb {

ParquetKeys &ParquetKeys::Get(ClientContext &context) {
	auto &cache = ObjectCache::GetObjectCache(context);
	if (!cache.Get<ParquetKeys>(ParquetKeys::ObjectType())) {
		cache.Put(ParquetKeys::ObjectType(), make_shared<ParquetKeys>());
	}
	return *cache.Get<ParquetKeys>(ParquetKeys::ObjectType());
}

void ParquetKeys::AddKey(const string &key_name, const string &key) {
	keys[key_name] = key;
}

bool ParquetKeys::HasKey(const string &key_name) const {
	return keys.find(key_name) != keys.end();
}

const string &ParquetKeys::GetKey(const string &key_name) const {
	D_ASSERT(HasKey(key_name));
	return keys.at(key_name);
}

string ParquetKeys::ObjectType() {
	return "parquet_keys";
}

string ParquetKeys::GetObjectType() {
	return ObjectType();
}

ParquetEncryptionConfig::ParquetEncryptionConfig(ClientContext &context_p) : context(context_p) {
}

ParquetEncryptionConfig::ParquetEncryptionConfig(ClientContext &context_p, const Value &arg)
    : ParquetEncryptionConfig(context_p) {
	if (arg.type().id() != LogicalTypeId::STRUCT) {
		throw BinderException("Parquet encryption_config must be of type STRUCT");
	}
	const auto &child_types = StructType::GetChildTypes(arg.type());
	auto &children = StructValue::GetChildren(arg);
	const auto &keys = ParquetKeys::Get(context);
	for (idx_t i = 0; i < StructType::GetChildCount(arg.type()); i++) {
		auto &struct_key = child_types[i].first;
		if (StringUtil::Lower(struct_key) == "footer_key") {
			const auto footer_key_name = StringValue::Get(children[i].DefaultCastAs(LogicalType::VARCHAR));
			if (!keys.HasKey(footer_key_name)) {
				throw BinderException(
				    "No key with name \"%s\" exists. Add it with PRAGMA add_parquet_key('<key_name>','<key>');",
				    footer_key_name);
			}
			footer_key = footer_key_name;
		} else if (StringUtil::Lower(struct_key) == "column_keys") {
			throw NotImplementedException("Parquet encryption_config column_keys not yet implemented");
		} else {
			throw BinderException("Unknown key in encryption_config \"%s\"", struct_key);
		}
	}
}

shared_ptr<ParquetEncryptionConfig> ParquetEncryptionConfig::Create(ClientContext &context, const Value &arg) {
	return shared_ptr<ParquetEncryptionConfig>(new ParquetEncryptionConfig(context, arg));
}

const string &ParquetEncryptionConfig::GetFooterKey() const {
	const auto &keys = ParquetKeys::Get(context);
	D_ASSERT(!footer_key.empty());
	D_ASSERT(keys.HasKey(footer_key));
	return keys.GetKey(footer_key);
}

using duckdb_apache::thrift::transport::TTransport;
//using AESGCMState = duckdb_mbedtls::MbedTlsWrapper::AESGCMState;
using AESGCMStateSSL = duckdb_openssl::openSSLWrapper::AESGCMStateSSL;
using duckdb_apache::thrift::protocol::TCompactProtocolFactoryT;

static void GenerateNonce(const data_ptr_t nonce) {
	duckdb_openssl::openSSLWrapper::AESGCMStateSSL::GenerateRandomData(nonce, ParquetCrypto::NONCE_BYTES);
	//duckdb_mbedtls::MbedTlsWrapper::GenerateRandomData(nonce, ParquetCrypto::NONCE_BYTES);
}

//! Encryption wrapper for a transport protocol
class EncryptionTransport : public TTransport {
public:

	EncryptionTransport(TProtocol &prot_p, const string &key)
	    : prot(prot_p), trans(*prot.getTransport()), aes(key),
	      allocator(Allocator::DefaultAllocator(), ParquetCrypto::CRYPTO_BLOCK_SIZE) {
		Initialize();
	}

	bool isOpen() const override {
		return trans.isOpen();
	}

	void open() override {
		trans.open();
	}

	void close() override {
		trans.close();
	}

	void write_virt(const uint8_t *buf, uint32_t len) override {
		memcpy(allocator.Allocate(len), buf, len);
	}

	uint32_t Finalize() {
		// Write length
		const auto ciphertext_length = allocator.SizeInBytes();
		const uint32_t total_length = nonce_bytes + ciphertext_length + tag_bytes;

		trans.write(const_data_ptr_cast(&total_length), ParquetCrypto::LENGTH_BYTES);
		// Write nonce at beginning of encrypted chunk
		trans.write(nonce, nonce_bytes);

		// Encrypt and write data
		data_t aes_buffer[ParquetCrypto::CRYPTO_BLOCK_SIZE];
		auto current = allocator.GetTail();
		// Loop through the whole chunk
		while (current != nullptr) {
			for (idx_t pos = 0; pos < current->current_position; pos += ParquetCrypto::CRYPTO_BLOCK_SIZE) {
				auto next = MinValue<idx_t>(current->current_position - pos, ParquetCrypto::CRYPTO_BLOCK_SIZE);
				auto write_size =
				    aes.Process(current->data.get() + pos, next, aes_buffer, ParquetCrypto::CRYPTO_BLOCK_SIZE);
				trans.write(aes_buffer, write_size);
			}
			current = current->prev;
		}

		// Finalize the last encrypted data
		// Tag only used for GCM
		data_t tag[ParquetCrypto::TAG_BYTES];
		auto write_size = aes.Finalize(aes_buffer, 0, tag, tag_bytes);
		trans.write(aes_buffer, write_size);
		// nothing is written here for CTR mode
		trans.write(tag, tag_bytes);

		return ParquetCrypto::LENGTH_BYTES + total_length;
	}

private:
	void Initialize() {

		// Generate nonce and initialize AES
		GenerateNonce(nonce);

		// TODO: Set Appropriate AES algorithm (ctr, gcm)
		// TODO: Set key size here)
		if (!aes.GetModeAES()) {
			// set nonce_bytes to 16 for CTR
			nonce_bytes = ParquetCrypto::TAG_BYTES;
			tag_bytes = 0;
			// For CTR: IVs are comprised of a 12-byte nonce
			// and a 4-byte initial counter field.
			// The first 31 bits of the initial counter field are set to 0
			// the last bit is set to 1.
			uint8_t iv[16];
			memset(iv, 0, nonce_bytes);
			iv[nonce_bytes - 1] = 1;
			duckdb::move(nonce, nonce + 12, iv);

		} else {
		    nonce_bytes = ParquetCrypto::NONCE_BYTES;
			tag_bytes = ParquetCrypto::TAG_BYTES;
		}

		aes.InitializeEncryption(nonce, nonce_bytes);
	}

private:
	//! Protocol and corresponding transport that we're wrapping
	TProtocol &prot;
	TTransport &trans;

	//! AES context
//	AESGCMState aes;

	//! AES Openssl Context;
	 AESGCMStateSSL aes;

	 //! Nonce length and tag differs
	 //! Between GCM and CTR mode
	 uint32_t tag_bytes;
	 uint32_t nonce_bytes;

	//! Nonce created by Initialize()
	data_t nonce[ParquetCrypto::NONCE_BYTES];

	//! Arena Allocator to fully materialize in memory before encrypting
	ArenaAllocator allocator;
};

//! Decryption wrapper for a transport protocol
class DecryptionTransport : public TTransport {
public:
	DecryptionTransport(TProtocol &prot_p, const string &key)
	    : prot(prot_p), trans(*prot.getTransport()), aes(key), read_buffer_size(0), read_buffer_offset(0) {
		Initialize();
	}

	uint32_t read_virt(uint8_t *buf, uint32_t len) override {
		const uint32_t result = len;

		if (len > transport_remaining - tag_bytes + read_buffer_size - read_buffer_offset) {
			throw InvalidInputException("Too many bytes requested from crypto buffer");
		}

		while (len != 0) {
			if (read_buffer_offset == read_buffer_size) {
				ReadBlock();
			}
			const auto next = MinValue(read_buffer_size - read_buffer_offset, len);
			memcpy(buf, read_buffer + read_buffer_offset, next);
			read_buffer_offset += next;
			buf += next;
			len -= next;
		}

		return result;
	}

	uint32_t Finalize() {
		if (read_buffer_offset != read_buffer_size) {
			throw InternalException("DecryptionTransport::Finalize was called with bytes remaining in read buffer");
		}

		// For GCM Mode a tag needs to be read at the end of an encrypted chunk
		// For CTR mode we just pass an empty tag
		data_t computed_tag[ParquetCrypto::TAG_BYTES];
		transport_remaining -= trans.read(computed_tag, tag_bytes);

		if (aes.Finalize(read_buffer, 0, computed_tag, tag_bytes) != 0) {
			throw InternalException("DecryptionTransport::Finalize was called with bytes remaining in AES context out");
		}

		return ParquetCrypto::LENGTH_BYTES + total_bytes;

		// Check tag manually; only used for mbedtls
//		data_t read_tag[ParquetCrypto::TAG_BYTES];
//		transport_remaining -= trans.read(read_tag, ParquetCrypto::TAG_BYTES);
//		if (memcmp(computed_tag, read_tag, ParquetCrypto::TAG_BYTES) != 0) {
//			throw InvalidInputException("Computed AES tag differs from read AES tag, are you using the right key?");
//		}
	}

	AllocatedData ReadAll() {

		D_ASSERT(transport_remaining == total_bytes - nonce_bytes);
		auto result = Allocator::DefaultAllocator().Allocate(transport_remaining);
		read_virt(result.get(), transport_remaining - tag_bytes);

		Finalize();
		return result;
	}

private:

	void Initialize() {
		// Read encoded length (don't add to read_bytes)
		data_t length_buf[ParquetCrypto::LENGTH_BYTES];
		trans.read(length_buf, ParquetCrypto::LENGTH_BYTES);
		total_bytes = Load<uint32_t>(length_buf);
		transport_remaining = total_bytes;

		// Set IV/Nonce size
		if (!aes.GetModeAES()) {
			// If CTR, iv = 16 Bytes
			nonce_bytes = ParquetCrypto::TAG_BYTES;
			tag_bytes = 0;
		} else {
			// If GCM, nonce = 12 Bytes
			nonce_bytes = ParquetCrypto::NONCE_BYTES;
			tag_bytes = ParquetCrypto::TAG_BYTES;
		}

		// Read nonce and initialize AES
		transport_remaining -= trans.read(nonce, nonce_bytes);
		aes.InitializeDecryption(nonce, nonce_bytes);
	}

	void ReadBlock() {
		// Read from transport into read_buffer at one AES block size offset (up to the tag)
		read_buffer_size = MinValue(ParquetCrypto::CRYPTO_BLOCK_SIZE, transport_remaining - tag_bytes);
		transport_remaining -= trans.read(read_buffer + AESGCMStateSSL::BLOCK_SIZE, read_buffer_size);

		// Decrypt from read_buffer + block size into read_buffer start (decryption can trail behind in same buffer)
#ifdef DEBUG
		auto size = aes.Process(read_buffer + AESGCMStateSSL::BLOCK_SIZE, read_buffer_size, read_buffer,
		                        ParquetCrypto::CRYPTO_BLOCK_SIZE + AESGCMStateSSL::BLOCK_SIZE);
		D_ASSERT(size == read_buffer_size);
#else
		aes.Process(read_buffer + AESGCMStateSSL::BLOCK_SIZE, read_buffer_size, read_buffer,
		            ParquetCrypto::CRYPTO_BLOCK_SIZE + AESGCMStateSSL::BLOCK_SIZE);
#endif
		read_buffer_offset = 0;
	}

private:
	//! Protocol and corresponding transport that we're wrapping
	TProtocol &prot;
	TTransport &trans;

	//! AES context and buffers
//	AESGCMState aes;

	//! AES context and buffers
	AESGCMStateSSL aes;

	//! We read/decrypt big blocks at a time
	data_t read_buffer[ParquetCrypto::CRYPTO_BLOCK_SIZE + AESGCMStateSSL::BLOCK_SIZE];
	uint32_t read_buffer_size;
	uint32_t read_buffer_offset;

	//! tag_bytes and nonce_bytes differ
	//! Between GCM and CTR mode
	uint32_t tag_bytes;
	uint32_t nonce_bytes;

	//! Remaining bytes to read, set by Initialize(), decremented by ReadBlock()
	uint32_t total_bytes;
	uint32_t transport_remaining;

	//! Nonce read by Initialize()
	data_t nonce[ParquetCrypto::NONCE_BYTES];
};

class SimpleReadTransport : public TTransport {
public:
	explicit SimpleReadTransport(data_ptr_t read_buffer_p, uint32_t read_buffer_size_p)
	    : read_buffer(read_buffer_p), read_buffer_size(read_buffer_size_p), read_buffer_offset(0) {
	}

	uint32_t read_virt(uint8_t *buf, uint32_t len) override {
		const auto remaining = read_buffer_size - read_buffer_offset;
		if (len > remaining) {
			return remaining;
		}
		memcpy(buf, read_buffer + read_buffer_offset, len);
		read_buffer_offset += len;
		return len;
	}

private:
	const data_ptr_t read_buffer;
	const uint32_t read_buffer_size;
	uint32_t read_buffer_offset;
};

uint32_t ParquetCrypto::Read(TBase &object, TProtocol &iprot, const string &key) {
	// Create decryption protocol
	TCompactProtocolFactoryT<DecryptionTransport> tproto_factory;
	auto dprot = tproto_factory.getProtocol(make_shared<DecryptionTransport>(iprot, key));
	auto &dtrans = reinterpret_cast<DecryptionTransport &>(*dprot->getTransport());

	// We have to read the whole thing otherwise thrift throws an error before we realize we're decryption is wrong
	auto all = dtrans.ReadAll();
	TCompactProtocolFactoryT<SimpleReadTransport> tsimple_proto_factory;
	auto simple_prot = tsimple_proto_factory.getProtocol(make_shared<SimpleReadTransport>(all.get(), all.GetSize()));

	// Read the object
	object.read(simple_prot.get());

	// we do nothing with what's returned here?
	return ParquetCrypto::LENGTH_BYTES + ParquetCrypto::NONCE_BYTES + all.GetSize() + ParquetCrypto::TAG_BYTES;
}

uint32_t ParquetCrypto::Write(const TBase &object, TProtocol &oprot, const string &key) {
	// Create encryption protocol
	TCompactProtocolFactoryT<EncryptionTransport> tproto_factory;
	auto eprot = tproto_factory.getProtocol(make_shared<EncryptionTransport>(oprot, key));
	auto &etrans = reinterpret_cast<EncryptionTransport &>(*eprot->getTransport());

	// Write the object in memory
	object.write(eprot.get());

	// Encrypt and write to oprot
	return etrans.Finalize();
}

uint32_t ParquetCrypto::ReadData(TProtocol &iprot, const data_ptr_t buffer, const uint32_t buffer_size,
                                 const string &key) {
	// Create decryption protocol
	TCompactProtocolFactoryT<DecryptionTransport> tproto_factory;
	auto dprot = tproto_factory.getProtocol(make_shared<DecryptionTransport>(iprot, key));
	auto &dtrans = reinterpret_cast<DecryptionTransport &>(*dprot->getTransport());

	// Read buffer
	dtrans.read(buffer, buffer_size);

	// Verify AES tag and read length
	return dtrans.Finalize();
}

uint32_t ParquetCrypto::WriteData(TProtocol &oprot, const const_data_ptr_t buffer, const uint32_t buffer_size,
                                  const string &key) {
	// FIXME: we know the size upfront so we could do a streaming write instead of this
	// Create encryption protocol
	TCompactProtocolFactoryT<EncryptionTransport> tproto_factory;
	auto eprot = tproto_factory.getProtocol(make_shared<EncryptionTransport>(oprot, key));
	auto &etrans = reinterpret_cast<EncryptionTransport &>(*eprot->getTransport());

	// Write the data in memory
	etrans.write(buffer, buffer_size);

	// Encrypt and write to oprot
	return etrans.Finalize();
}

void ParquetCrypto::AddKey(ClientContext &context, const FunctionParameters &parameters) {
	const auto &key_name = StringValue::Get(parameters.values[0]);
	const auto &key = StringValue::Get(parameters.values[1]);
	if (!AESGCMStateSSL::ValidKey(key)) {
		throw InvalidInputException(
		    "Invalid AES key. Must have a length of 128, 192, or 256 bits (16, 24, or 32 bytes)");
	}
	auto &keys = ParquetKeys::Get(context);
	keys.AddKey(key_name, key);
}

} // namespace duckdb

#include "duckdb/common/bswap.hpp"
#include "duckdb/function/scalar/compressed_materialization_functions.hpp"

namespace duckdb {

static string StringCompressFunctionName(const LogicalType &result_type) {
	return StringUtil::Format("__internal_compress_string_%s",
	                          StringUtil::Lower(LogicalTypeIdToString(result_type.id())));
}

template <class T>
const uint8_t &FirstByteReference(const T &v) {
	return reinterpret_cast<const uint8_t *>(&v)[0];
}

template <class T>
uint8_t &LastByteReference(T &v) {
	return reinterpret_cast<uint8_t *>(&v)[sizeof(T) - 1];
}

template <class T>
const uint8_t &LastByteReference(const T &v) {
	return reinterpret_cast<const uint8_t *>(&v)[sizeof(T) - 1];
}

template <class RESULT_TYPE>
static inline RESULT_TYPE StringCompressInternal(const string_t &input) {
	D_ASSERT(input.GetSize() < sizeof(RESULT_TYPE));
	RESULT_TYPE result;
	if (sizeof(RESULT_TYPE) <= string_t::INLINE_LENGTH) {
		memcpy(&result, input.GetPrefix(), sizeof(RESULT_TYPE));
	} else if (input.GetSize() <= string_t::INLINE_LENGTH) {
		memcpy(&result, input.GetPrefix(), string_t::INLINE_LENGTH);
		memset(data_ptr_t(&result) + string_t::INLINE_LENGTH, '\0', sizeof(RESULT_TYPE) - string_t::INLINE_LENGTH);
	} else {
		result = 0;
		memcpy(&result, input.GetData(), input.GetSize());
	}
	LastByteReference<RESULT_TYPE>(result) = input.GetSize();
	return BSwap<RESULT_TYPE>(result);
}

template <class RESULT_TYPE>
static inline RESULT_TYPE StringCompress(const string_t &input) {
	return StringCompressInternal<RESULT_TYPE>(input);
}

template <class RESULT_TYPE>
static inline RESULT_TYPE MiniStringCompress(const string_t &input) {
	if (sizeof(RESULT_TYPE) <= string_t::INLINE_LENGTH) {
		return input.GetSize() + *reinterpret_cast<const uint8_t *>(input.GetPrefix());
	} else {
		return input.GetSize() + *reinterpret_cast<const uint8_t *>(input.GetDataUnsafe());
	}
}

template <>
inline uint8_t StringCompress(const string_t &input) {
	return MiniStringCompress<uint8_t>(input);
}

template <class RESULT_TYPE>
static void StringCompressFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	UnaryExecutor::Execute<string_t, RESULT_TYPE>(args.data[0], result, args.size(), StringCompress<RESULT_TYPE>);
}

template <class RESULT_TYPE>
static scalar_function_t GetStringCompressFunction(const LogicalType &result_type) {
	return StringCompressFunction<RESULT_TYPE>;
}

static scalar_function_t GetStringCompressFunctionSwitch(const LogicalType &result_type) {
	switch (result_type.id()) {
	case LogicalTypeId::UTINYINT:
		return GetStringCompressFunction<uint8_t>(result_type);
	case LogicalTypeId::USMALLINT:
		return GetStringCompressFunction<uint16_t>(result_type);
	case LogicalTypeId::UINTEGER:
		return GetStringCompressFunction<uint32_t>(result_type);
	case LogicalTypeId::UBIGINT:
		return GetStringCompressFunction<uint64_t>(result_type);
	case LogicalTypeId::HUGEINT:
		return GetStringCompressFunction<hugeint_t>(result_type);
	default:
		throw InternalException("Unexpected type in GetStringCompressFunctionSwitch");
	}
}

static string StringDecompressFunctionName() {
	return "__internal_decompress_string";
}

struct StringDecompressLocalState : public FunctionLocalState {
public:
	explicit StringDecompressLocalState(ClientContext &context) : allocator(Allocator::Get(context)) {
	}

	static unique_ptr<FunctionLocalState> Init(ExpressionState &state, const BoundFunctionExpression &expr,
	                                           FunctionData *bind_data) {
		return make_uniq<StringDecompressLocalState>(state.GetContext());
	}

public:
	ArenaAllocator allocator;
};

template <class INPUT_TYPE>
static inline string_t StringDecompress(const INPUT_TYPE &input, ArenaAllocator &allocator) {
	if (sizeof(INPUT_TYPE) <= string_t::INLINE_LENGTH) {
		static constexpr const idx_t MEMCPY_LENGTH = sizeof(INPUT_TYPE);
		static constexpr const idx_t MEMSET_LENGTH = string_t::INLINE_LENGTH - MEMCPY_LENGTH + 1;

		const auto input_swapped = BSwap<INPUT_TYPE>(input);
		const uint32_t string_size = LastByteReference<INPUT_TYPE>(input_swapped);

		string_t result(string_size);
		memcpy(result.GetPrefixWriteable(), &input_swapped, MEMCPY_LENGTH);
		memset(result.GetPrefixWriteable() + MEMCPY_LENGTH - 1, '\0', MEMSET_LENGTH);
		return result;
	}

	const uint32_t string_size = FirstByteReference<INPUT_TYPE>(input);
	if (string_size <= string_t::INLINE_LENGTH) {
		string_t result(string_size);
		const auto input_swapped = BSwap<INPUT_TYPE>(input);
		memcpy(result.GetPrefixWriteable(), &input_swapped, string_t::INLINE_LENGTH);
		return result;
	} else {
		auto ptr = reinterpret_cast<INPUT_TYPE *>(allocator.Allocate(sizeof(INPUT_TYPE)));
		*ptr = BSwap<INPUT_TYPE>(input);
		return string_t(const_char_ptr_cast(ptr), string_size);
	}
}

template <class INPUT_TYPE>
static inline string_t MiniStringDecompress(const INPUT_TYPE &input, ArenaAllocator &allocator) {
	if (sizeof(INPUT_TYPE) <= string_t::INLINE_LENGTH) {
		const auto min = MinValue<INPUT_TYPE>(1, input);
		string_t result(min);
		memset(result.GetPrefixWriteable(), '\0', string_t::INLINE_BYTES);
		*reinterpret_cast<uint8_t *>(result.GetPrefixWriteable()) = input - min;
		return result;
	} else if (input == 0) {
		return string_t(uint32_t(0));
	} else {
		auto ptr = allocator.Allocate(1);
		*ptr = input - 1;
		return string_t(const_char_ptr_cast(ptr), 1);
	}
}

template <>
inline string_t StringDecompress(const uint8_t &input, ArenaAllocator &allocator) {
	return MiniStringDecompress<uint8_t>(input, allocator);
}

template <class INPUT_TYPE>
static void StringDecompressFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &allocator = ExecuteFunctionState::GetFunctionState(state)->Cast<StringDecompressLocalState>().allocator;
	allocator.Reset();
	UnaryExecutor::Execute<INPUT_TYPE, string_t>(args.data[0], result, args.size(), [&](const INPUT_TYPE &input) {
		return StringDecompress<INPUT_TYPE>(input, allocator);
	});
}

template <class INPUT_TYPE>
static scalar_function_t GetStringDecompressFunction(const LogicalType &input_type) {
	return StringDecompressFunction<INPUT_TYPE>;
}

static scalar_function_t GetStringDecompressFunctionSwitch(const LogicalType &input_type) {
	switch (input_type.id()) {
	case LogicalTypeId::UTINYINT:
		return GetStringDecompressFunction<uint8_t>(input_type);
	case LogicalTypeId::USMALLINT:
		return GetStringDecompressFunction<uint16_t>(input_type);
	case LogicalTypeId::UINTEGER:
		return GetStringDecompressFunction<uint32_t>(input_type);
	case LogicalTypeId::UBIGINT:
		return GetStringDecompressFunction<uint64_t>(input_type);
	case LogicalTypeId::HUGEINT:
		return GetStringDecompressFunction<hugeint_t>(input_type);
	default:
		throw InternalException("Unexpected type in GetStringDecompressFunctionSwitch");
	}
}

static void CMStringCompressSerialize(FieldWriter &writer, const FunctionData *bind_data_p,
                                      const ScalarFunction &function) {
	writer.WriteRegularSerializableList(function.arguments);
	writer.WriteSerializable(function.return_type);
}

unique_ptr<FunctionData> CMStringCompressDeserialize(ClientContext &context, FieldReader &reader,
                                                     ScalarFunction &bound_function) {
	bound_function.arguments = reader.template ReadRequiredSerializableList<LogicalType, LogicalType>();
	bound_function.function =
	    GetStringCompressFunctionSwitch(reader.ReadRequiredSerializable<LogicalType, LogicalType>());
	return nullptr;
}

ScalarFunction CMStringCompressFun::GetFunction(const LogicalType &result_type) {
	ScalarFunction result(StringCompressFunctionName(result_type), {LogicalType::VARCHAR}, result_type,
	                      GetStringCompressFunctionSwitch(result_type), CompressedMaterializationFunctions::Bind);
	result.serialize = CMStringCompressSerialize;
	result.deserialize = CMStringCompressDeserialize;
	return result;
}

void CMStringCompressFun::RegisterFunction(BuiltinFunctions &set) {
	for (const auto &result_type : CompressedMaterializationFunctions::StringTypes()) {
		set.AddFunction(CMStringCompressFun::GetFunction(result_type));
	}
}

static void CMStringDecompressSerialize(FieldWriter &writer, const FunctionData *bind_data_p,
                                        const ScalarFunction &function) {
	writer.WriteRegularSerializableList(function.arguments);
}

unique_ptr<FunctionData> CMStringDecompressDeserialize(ClientContext &context, FieldReader &reader,
                                                       ScalarFunction &bound_function) {
	bound_function.arguments = reader.template ReadRequiredSerializableList<LogicalType, LogicalType>();
	bound_function.function = GetStringDecompressFunctionSwitch(bound_function.arguments[0]);
	return nullptr;
}

ScalarFunction CMStringDecompressFun::GetFunction(const LogicalType &input_type) {
	ScalarFunction result(StringDecompressFunctionName(), {input_type}, LogicalType::VARCHAR,
	                      GetStringDecompressFunctionSwitch(input_type), CompressedMaterializationFunctions::Bind,
	                      nullptr, nullptr, StringDecompressLocalState::Init);
	result.serialize = CMStringDecompressSerialize;
	result.deserialize = CMStringDecompressDeserialize;
	return result;
}

static ScalarFunctionSet GetStringDecompressFunctionSet() {
	ScalarFunctionSet set(StringDecompressFunctionName());
	for (const auto &input_type : CompressedMaterializationFunctions::StringTypes()) {
		set.AddFunction(CMStringDecompressFun::GetFunction(input_type));
	}
	return set;
}

void CMStringDecompressFun::RegisterFunction(BuiltinFunctions &set) {
	set.AddFunction(GetStringDecompressFunctionSet());
}

} // namespace duckdb

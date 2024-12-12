#include "duckdb/common/arrow/arrow_type_extension.hpp"
#include "duckdb/common/types/hash.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/function/table/arrow/arrow_duck_schema.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/common/arrow/arrow_converter.hpp"
#include "duckdb/common/arrow/schema_metadata.hpp"

namespace duckdb {

ArrowTypeExtension::ArrowTypeExtension(string extension_name, string arrow_format, shared_ptr<ArrowType> type_p)
    : extension_info(std::move(extension_name), {}, {}, std::move(arrow_format)), type(std::move(type_p)) {
}

ArrowTypeExtensionInfo::ArrowTypeExtensionInfo(string extension_name, string vendor_name, string type_name,
                                               string arrow_format)
    : extension_name(std::move(extension_name)), vendor_name(std::move(vendor_name)), type_name(std::move(type_name)),
      arrow_format(std::move(arrow_format)) {
}

hash_t ArrowTypeExtensionInfo::GetHash() const {
	const auto h_extension = Hash(extension_name.c_str());
	const auto h_vendor = Hash(vendor_name.c_str());
	const auto h_type = Hash(type_name.c_str());
	const auto h_arrow_format = Hash(arrow_format.c_str());
	return CombineHash(h_extension, CombineHash(h_vendor, CombineHash(h_type, h_arrow_format)));
}

TypeInfo::TypeInfo() : type() {
}

TypeInfo::TypeInfo(const LogicalType &type_p) : alias(type_p.GetAlias()), type(type_p.id()) {
}

TypeInfo::TypeInfo(string alias) : alias(std::move(alias)), type(LogicalTypeId::ANY) {
}

hash_t TypeInfo::GetHash() const {
	const auto h_type_id = Hash(type);
	const auto h_alias = Hash(alias.c_str());
	return CombineHash(h_type_id, h_alias);
}

bool TypeInfo::operator==(const TypeInfo &other) const {
	return alias == other.alias && type == other.type;
}

string ArrowTypeExtensionInfo::ToString() const {
	std::ostringstream info;
	info << "Extension Name: " << extension_name << "\n";
	if (!vendor_name.empty()) {
		info << "Vendor: " << vendor_name << "\n";
	}
	if (!type_name.empty()) {
		info << "Type: " << type_name << "\n";
	}
	if (!arrow_format.empty()) {
		info << "Format: " << arrow_format << "\n";
	}
	return info.str();
}

string ArrowTypeExtensionInfo::GetExtensionName() const {
	return extension_name;
}

string ArrowTypeExtensionInfo::GetVendorName() const {
	return vendor_name;
}

string ArrowTypeExtensionInfo::GetTypeName() const {
	return type_name;
}

string ArrowTypeExtensionInfo::GetArrowFormat() const {
	return arrow_format;
}

void ArrowTypeExtensionInfo::SetArrowFormat(string arrow_format_p) {
	arrow_format = std::move(arrow_format_p);
}

bool ArrowTypeExtensionInfo::IsCanonical() const {
	D_ASSERT((!vendor_name.empty() && !type_name.empty()) || (vendor_name.empty() && type_name.empty()));
	return vendor_name.empty();
}

bool ArrowTypeExtensionInfo::operator==(const ArrowTypeExtensionInfo &other) const {
	return extension_name == other.extension_name && type_name == other.type_name && vendor_name == other.vendor_name &&
	       arrow_format == other.arrow_format;
}

ArrowTypeExtension::ArrowTypeExtension(string vendor_name, string type_name, string arrow_format,
                                       shared_ptr<ArrowType> type_p)
    : extension_info(ArrowTypeExtensionInfo::ARROW_EXTENSION_NON_CANONICAL, std::move(vendor_name),
                     std::move(type_name), std::move(arrow_format)),
      type(std::move(type_p)) {
}

ArrowTypeExtension::ArrowTypeExtension(string extension_name, populate_arrow_schema_t populate_arrow_schema,
                                       get_type_t get_type, shared_ptr<ArrowType> type_p)
    : populate_arrow_schema(populate_arrow_schema), get_type(get_type),
      extension_info(std::move(extension_name), {}, {}, {}), type(std::move(type_p)) {
}

ArrowTypeExtension::ArrowTypeExtension(string vendor_name, string type_name,
                                       populate_arrow_schema_t populate_arrow_schema, get_type_t get_type,
                                       shared_ptr<ArrowType> type_p)
    : populate_arrow_schema(populate_arrow_schema), get_type(get_type),
      extension_info(ArrowTypeExtensionInfo::ARROW_EXTENSION_NON_CANONICAL, std::move(vendor_name),
                     std::move(type_name), {}),
      type(std::move(type_p)) {
}

ArrowTypeExtensionInfo ArrowTypeExtension::GetInfo() const {
	return extension_info;
}

shared_ptr<ArrowType> ArrowTypeExtension::GetType(const string &format,
                                                  const ArrowSchemaMetadata &schema_metadata) const {
	if (get_type) {
		return get_type(format, schema_metadata);
	}
	return type;
}

LogicalTypeId ArrowTypeExtension::GetLogicalTypeId() const {
	return type->GetDuckType().id();
}

LogicalType ArrowTypeExtension::GetLogicalType() const {
	return type->GetDuckType();
}

bool ArrowTypeExtension::HasType() const {
	return type.get() != nullptr;
}

void ArrowTypeExtension::PopulateArrowSchema(DuckDBArrowSchemaHolder &root_holder, ArrowSchema &child,
                                             const LogicalType &duckdb_type, ClientContext &context,
                                             ArrowTypeExtension &extension) {
	if (extension.populate_arrow_schema) {
		extension.populate_arrow_schema(root_holder, child, duckdb_type, context, extension);
		return;
	}

	auto format = make_unsafe_uniq_array<char>(extension.extension_info.GetArrowFormat().size());
	idx_t i = 0;
	for (auto &c : extension.extension_info.GetArrowFormat()) {
		format[i++] = c;
	}
	// We do the default way of populating the schema
	root_holder.extension_format.emplace_back(std::move(format));

	child.format = root_holder.extension_format.back().get();
	ArrowSchemaMetadata schema_metadata;
	if (extension.extension_info.IsCanonical()) {
		schema_metadata = ArrowSchemaMetadata::ArrowCanonicalType(extension.extension_info.GetExtensionName());
	} else {
		schema_metadata = ArrowSchemaMetadata::NonCanonicalType(extension.extension_info.GetTypeName(),
		                                                        extension.extension_info.GetVendorName());
	}
	root_holder.metadata_info.emplace_back(schema_metadata.SerializeMetadata());
	child.metadata = root_holder.metadata_info.back().get();
}

void DBConfig::RegisterArrowExtension(const ArrowTypeExtension &extension) const {
	lock_guard<mutex> l(encoding_functions->lock);
	auto extension_info = extension.GetInfo();
	if (arrow_extensions->type_extensions.find(extension_info) != arrow_extensions->type_extensions.end()) {
		throw NotImplementedException("Arrow Extension with configuration %s is already registered",
		                              extension_info.ToString());
	}
	arrow_extensions->type_extensions[extension_info] = extension;
	if (extension.HasType()) {
		const TypeInfo type_info(extension.GetLogicalType());
		arrow_extensions->type_to_info[type_info].push_back(extension_info);
		return;
	}
	const TypeInfo type_info(extension.GetInfo().GetExtensionName());
	arrow_extensions->type_to_info[type_info].push_back(extension_info);
}

ArrowTypeExtension DBConfig::GetArrowExtension(ArrowTypeExtensionInfo info) const {
	if (arrow_extensions->type_extensions.find(info) == arrow_extensions->type_extensions.end()) {
		info.SetArrowFormat("");
		if (arrow_extensions->type_extensions.find(info) == arrow_extensions->type_extensions.end()) {
			throw NotImplementedException("Arrow Extension with configuration:\n%s not yet registered",
			                              info.ToString());
		}
	}
	return arrow_extensions->type_extensions[info];
}

ArrowTypeExtension DBConfig::GetArrowExtension(const LogicalType &type) const {
	TypeInfo type_info(type);
	if (!arrow_extensions->type_to_info[type_info].empty()) {
		return GetArrowExtension(arrow_extensions->type_to_info[type_info].front());
	}
	type_info.type = LogicalTypeId::ANY;
	return GetArrowExtension(arrow_extensions->type_to_info[type_info].front());
}

bool DBConfig::HasArrowExtension(const LogicalType &type) const {
	TypeInfo type_info(type);
	if (!arrow_extensions->type_to_info[type_info].empty()) {
		return true;
	}
	type_info.type = LogicalTypeId::ANY;
	return !arrow_extensions->type_to_info[type_info].empty();
}

struct ArrowJson {
	static shared_ptr<ArrowType> GetType(const string &format, const ArrowSchemaMetadata &schema_metadata) {
		if (format == "u") {
			return make_shared_ptr<ArrowType>(LogicalType::JSON(),
			                                  make_uniq<ArrowStringInfo>(ArrowVariableSizeType::NORMAL));
		} else if (format == "U") {
			return make_shared_ptr<ArrowType>(LogicalType::JSON(),
			                                  make_uniq<ArrowStringInfo>(ArrowVariableSizeType::SUPER_SIZE));
		} else if (format == "vu") {
			return make_shared_ptr<ArrowType>(LogicalType::JSON(),
			                                  make_uniq<ArrowStringInfo>(ArrowVariableSizeType::VIEW));
		}
		throw InvalidInputException("Arrow extension type \"%s\" not supported for arrow.json", format.c_str());
	}

	static void PopulateSchema(DuckDBArrowSchemaHolder &root_holder, ArrowSchema &schema, const LogicalType &type,
	                           ClientContext &context, ArrowTypeExtension &extension) {
		ArrowSchemaMetadata schema_metadata =
		    ArrowSchemaMetadata::ArrowCanonicalType(extension.GetInfo().GetExtensionName());
		root_holder.metadata_info.emplace_back(schema_metadata.SerializeMetadata());
		schema.metadata = root_holder.metadata_info.back().get();
		auto options = context.GetClientProperties();
		if (options.produce_arrow_string_view) {
			schema.format = "vu";
		} else {
			if (options.arrow_offset_size == ArrowOffsetSize::LARGE) {
				schema.format = "U";
			} else {
				schema.format = "u";
			}
		}
	}
};

struct ArrowBit {
	static shared_ptr<ArrowType> GetType(const string &format, const ArrowSchemaMetadata &schema_metadata) {
		if (format == "z") {
			return make_shared_ptr<ArrowType>(LogicalType::BIT,
			                                  make_uniq<ArrowStringInfo>(ArrowVariableSizeType::NORMAL));
		} else if (format == "Z") {
			return make_shared_ptr<ArrowType>(LogicalType::BIT,
			                                  make_uniq<ArrowStringInfo>(ArrowVariableSizeType::SUPER_SIZE));
		}
		throw InvalidInputException("Arrow extension type \"%s\" not supported for BIT type", format.c_str());
	}

	static void PopulateSchema(DuckDBArrowSchemaHolder &root_holder, ArrowSchema &schema, const LogicalType &type,
	                           ClientContext &context, ArrowTypeExtension &extension) {
		ArrowSchemaMetadata schema_metadata = ArrowSchemaMetadata::NonCanonicalType(
		    extension.GetInfo().GetTypeName(), extension.GetInfo().GetVendorName());
		root_holder.metadata_info.emplace_back(schema_metadata.SerializeMetadata());
		schema.metadata = root_holder.metadata_info.back().get();
		auto options = context.GetClientProperties();
		if (options.arrow_offset_size == ArrowOffsetSize::LARGE) {
			schema.format = "Z";
		} else {
			schema.format = "z";
		}
	}
};

struct ArrowVarint {
	static shared_ptr<ArrowType> GetType(const string &format, const ArrowSchemaMetadata &schema_metadata) {
		if (format == "z") {
			return make_shared_ptr<ArrowType>(LogicalType::VARINT,
			                                  make_uniq<ArrowStringInfo>(ArrowVariableSizeType::NORMAL));
		} else if (format == "Z") {
			return make_shared_ptr<ArrowType>(LogicalType::VARINT,
			                                  make_uniq<ArrowStringInfo>(ArrowVariableSizeType::SUPER_SIZE));
		}
		throw InvalidInputException("Arrow extension type \"%s\" not supported for Varint", format.c_str());
	}

	static void PopulateSchema(DuckDBArrowSchemaHolder &root_holder, ArrowSchema &schema, const LogicalType &type,
	                           ClientContext &context, ArrowTypeExtension &extension) {
		ArrowSchemaMetadata schema_metadata = ArrowSchemaMetadata::NonCanonicalType(
		    extension.GetInfo().GetTypeName(), extension.GetInfo().GetVendorName());
		root_holder.metadata_info.emplace_back(schema_metadata.SerializeMetadata());
		schema.metadata = root_holder.metadata_info.back().get();
		auto options = context.GetClientProperties();
		if (options.arrow_offset_size == ArrowOffsetSize::LARGE) {
			schema.format = "Z";
		} else {
			schema.format = "z";
		}
	}
};

void ArrowTypeExtensionSet::Initialize(DBConfig &config) {
	// Types that are 1:1
	config.RegisterArrowExtension({"arrow.uuid", "w:16", make_shared_ptr<ArrowType>(LogicalType::UUID)});
	config.RegisterArrowExtension({"DuckDB", "hugeint", "w:16", make_shared_ptr<ArrowType>(LogicalType::HUGEINT)});
	config.RegisterArrowExtension({"DuckDB", "uhugeint", "w:16", make_shared_ptr<ArrowType>(LogicalType::UHUGEINT)});
	config.RegisterArrowExtension(
	    {"DuckDB", "time_tz", "w:8",
	     make_shared_ptr<ArrowType>(LogicalType::TIME_TZ,
	                                make_uniq<ArrowDateTimeInfo>(ArrowDateTimeType::MICROSECONDS))});

	// Types that are 1:n
	config.RegisterArrowExtension({"arrow.json", &ArrowJson::PopulateSchema, &ArrowJson::GetType,
	                               make_shared_ptr<ArrowType>(LogicalType::VARCHAR)});
	config.RegisterArrowExtension(
	    {"DuckDB", "bit", &ArrowBit::PopulateSchema, &ArrowBit::GetType, make_shared_ptr<ArrowType>(LogicalType::BIT)});
	config.RegisterArrowExtension({"DuckDB", "varint", &ArrowVarint::PopulateSchema, &ArrowVarint::GetType,
	                               make_shared_ptr<ArrowType>(LogicalType::VARINT)});
}
} // namespace duckdb

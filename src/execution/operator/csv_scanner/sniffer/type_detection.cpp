#include "duckdb/common/operator/decimal_cast_operators.hpp"
namespace duckdb {
struct TryCastDecimalOperator {
	template <class OP, class T>
	static bool Operation(string_t input, uint8_t width, uint8_t scale) {
		T result;
		string error_message;
		return OP::Operation(input, result, &error_message, width, scale);
	}
};

struct TryCastFloatingOperator {
	template <class OP, class T>
	static bool Operation(string_t input) {
		T result;
		string error_message;
		return OP::Operation(input, result, &error_message);
	}
};

bool TryCastDecimalValueCommaSeparated(const string_t &value_str, const LogicalType &sql_type) {
	auto width = DecimalType::GetWidth(sql_type);
	auto scale = DecimalType::GetScale(sql_type);
	switch (sql_type.InternalType()) {
	case PhysicalType::INT16:
		return TryCastDecimalOperator::Operation<TryCastToDecimalCommaSeparated, int16_t>(value_str, width, scale);
	case PhysicalType::INT32:
		return TryCastDecimalOperator::Operation<TryCastToDecimalCommaSeparated, int32_t>(value_str, width, scale);
	case PhysicalType::INT64:
		return TryCastDecimalOperator::Operation<TryCastToDecimalCommaSeparated, int64_t>(value_str, width, scale);
	case PhysicalType::INT128:
		return TryCastDecimalOperator::Operation<TryCastToDecimalCommaSeparated, hugeint_t>(value_str, width, scale);
	default:
		throw InternalException("Unimplemented physical type for decimal");
	}
}

bool TryCastFloatingValueCommaSeparated(const string_t &value_str, const LogicalType &sql_type) {
	switch (sql_type.InternalType()) {
	case PhysicalType::DOUBLE:
		return TryCastFloatingOperator::Operation<TryCastErrorMessageCommaSeparated, double>(value_str);
	case PhysicalType::FLOAT:
		return TryCastFloatingOperator::Operation<TryCastErrorMessageCommaSeparated, float>(value_str);
	default:
		throw InternalException("Unimplemented physical type for floating");
	}
}

bool CSVSniffer::TryCastValue(const Value &value, const LogicalType &sql_type) {
	if (value.IsNull()) {
		return true;
	}
	if (options.has_format.find(LogicalTypeId::DATE)->second && sql_type.id() == LogicalTypeId::DATE) {
		date_t result;
		string error_message;
		return options.date_format.find(LogicalTypeId::DATE)
		    ->second.TryParseDate(string_t(StringValue::Get(value)), result, error_message);
	} else if (options.has_format.find(LogicalTypeId::TIMESTAMP)->second && sql_type.id() == LogicalTypeId::TIMESTAMP) {
		timestamp_t result;
		string error_message;
		return options.date_format.find(LogicalTypeId::TIMESTAMP)
		    ->second.TryParseTimestamp(string_t(StringValue::Get(value)), result, error_message);
	} else if (options.decimal_separator != "." && sql_type.id() == LogicalTypeId::DECIMAL) {
		return TryCastDecimalValueCommaSeparated(string_t(StringValue::Get(value)), sql_type);
	} else if (options.decimal_separator != "." &&
	           ((sql_type.id() == LogicalTypeId::FLOAT) || (sql_type.id() == LogicalTypeId::DOUBLE))) {
		return TryCastFloatingValueCommaSeparated(string_t(StringValue::Get(value)), sql_type);
	} else {
		Value new_value;
		string error_message;
		return value.TryCastAs(buffer_manager->context, sql_type, new_value, &error_message, true);
	}
}

void CSVSniffer::SetDateFormat(CSVStateMachine &candidate, const string &format_specifier,
                               const LogicalTypeId &sql_type) {
	candidate.options.has_format[sql_type] = true;
	auto &date_format = candidate.options.date_format[sql_type];
	date_format.format_specifier = format_specifier;
	StrTimeFormat::ParseFormatSpecifier(date_format.format_specifier, date_format);
}

void CSVSniffer::DetectTypes() {
	idx_t min_varchar_cols = best_num_cols + 1;
	vector<LogicalType> return_types;
	// check which info candidate leads to minimum amount of non-varchar columns...
	for (auto &candidate : candidates) {
		vector<vector<LogicalType>> info_sql_types_candidates(candidate->options.num_cols,
		                                                      options.auto_type_candidates);
		std::map<LogicalTypeId, bool> has_format_candidates;
		std::map<LogicalTypeId, vector<string>> format_candidates;
		for (const auto &t : format_template_candidates) {
			has_format_candidates[t.first] = false;
			format_candidates[t.first].clear();
		}

		if (candidate->options.num_cols == 0) {
			continue;
		}

		// Set all return_types to VARCHAR so we can do datatype detection based on VARCHAR values
		return_types.clear();
		return_types.assign(candidate->options.num_cols, LogicalType::VARCHAR);

		// Reset candidate for parsing
		candidate->Reset();

		// Parse chunk and read csv with info candidate
		vector<vector<Value>> values(STANDARD_VECTOR_SIZE);
		candidate->SniffValue(values);
		for (idx_t row_idx = 1; row_idx < values.size(); row_idx++) {
			for (idx_t col = 0; col < values[row_idx].size(); col++) {
				auto &col_type_candidates = info_sql_types_candidates[col];
				while (col_type_candidates.size() > 1) {
					const auto &sql_type = col_type_candidates.back();
					// try cast from string to sql_type
					auto dummy_val = values[row_idx][col];
					// try formatting for date types if the user did not specify one and it starts with numeric values.
					string separator;
					bool has_format_is_set = options.has_format.find(sql_type.id())->second;
					if (has_format_candidates.count(sql_type.id()) && !has_format_is_set && !dummy_val.IsNull() &&
					    StartsWithNumericDate(separator, StringValue::Get(dummy_val))) {
						// generate date format candidates the first time through
						auto &type_format_candidates = format_candidates[sql_type.id()];
						const auto had_format_candidates = has_format_candidates[sql_type.id()];
						if (!has_format_candidates[sql_type.id()]) {
							has_format_candidates[sql_type.id()] = true;
							// order by preference
							auto entry = format_template_candidates.find(sql_type.id());
							if (entry != format_template_candidates.end()) {
								const auto &format_template_list = entry->second;
								for (const auto &t : format_template_list) {
									const auto format_string = GenerateDateFormat(separator, t);
									// don't parse ISO 8601
									if (format_string.find("%Y-%m-%d") == string::npos) {
										type_format_candidates.emplace_back(format_string);
									}
								}
							}
							//	initialise the first candidate
							candidate->options.has_format[sql_type.id()] = true;
							//	all formats are constructed to be valid
							SetDateFormat(*candidate, type_format_candidates.back(), sql_type.id());
						}
						// check all formats and keep the first one that works
						StrpTimeFormat::ParseResult result;
						auto save_format_candidates = type_format_candidates;
						while (!type_format_candidates.empty()) {
							//	avoid using exceptions for flow control...
							auto &current_format = candidate->options.date_format[sql_type.id()];
							if (current_format.Parse(StringValue::Get(dummy_val), result)) {
								break;
							}
							//	doesn't work - move to the next one
							type_format_candidates.pop_back();
							candidate->options.has_format[sql_type.id()] = (!type_format_candidates.empty());
							if (!type_format_candidates.empty()) {
								SetDateFormat(*candidate, type_format_candidates.back(), sql_type.id());
							}
						}
						//	if none match, then this is not a value of type sql_type,
						if (type_format_candidates.empty()) {
							//	so restore the candidates that did work.
							//	or throw them out if they were generated by this value.
							if (had_format_candidates) {
								type_format_candidates.swap(save_format_candidates);
								if (!type_format_candidates.empty()) {
									SetDateFormat(*candidate, type_format_candidates.back(), sql_type.id());
								}
							} else {
								has_format_candidates[sql_type.id()] = false;
							}
						}
					}
					// try cast from string to sql_type
					if (TryCastValue(dummy_val, sql_type)) {
						break;
					} else {
						col_type_candidates.pop_back();
					}
				}
			}
		}

		idx_t varchar_cols = 0;

		for (idx_t col = 0; col < info_sql_types_candidates.size(); col++) {
			auto &col_type_candidates = info_sql_types_candidates[col];
			// check number of varchar columns
			const auto &col_type = col_type_candidates.back();
			if (col_type == LogicalType::VARCHAR) {
				varchar_cols++;
			}
		}

		// it's good if the dialect creates more non-varchar columns, but only if we sacrifice < 30% of best_num_cols.
		if (varchar_cols < min_varchar_cols && info_sql_types_candidates.size() > (best_num_cols * 0.7)) {
			// we have a new best_options candidate
			best_candidate = candidate;
			min_varchar_cols = varchar_cols;
			best_sql_types_candidates = info_sql_types_candidates;
			best_format_candidates = format_candidates;
			best_header_row = values[0];
		}
	}

	if (!best_candidate || best_format_candidates.empty() || best_header_row.empty()) {
		throw InvalidInputException(
		    "Error in file \"%s\": CSV options could not be auto-detected. Consider setting parser options manually.",
		    options.file_path);
	}

	for (const auto &best : best_format_candidates) {
		if (!best.second.empty()) {
			SetDateFormat(*best_candidate, best.second.back(), best.first);
		}
	}
}

} // namespace duckdb

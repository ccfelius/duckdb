#include "duckdb/common/types/time.hpp"
#include "duckdb/common/types/timestamp.hpp"

#include "duckdb/common/string_util.hpp"
#include "duckdb/common/exception.hpp"

#include <cstring>
#include <sstream>
#include <cctype>

namespace duckdb {
using namespace std;

// string format is hh:mm:ssZ
// Z is optional
// ISO 8601

// Taken from MonetDB mtime.c
#define DD_TIME(h, m, s, x)                                                                                            \
	((h) >= 0 && (h) < 24 && (m) >= 0 && (m) < 60 && (s) >= 0 && (s) <= 60 && (x) >= 0 && (x) < 1000)

static dtime_t time_to_number(int hour, int min, int sec, int msec) {
	if (!DD_TIME(hour, min, sec, msec)) {
		throw ParserException("Invalid time hour=%d, min=%d, sec=%d, msec=%d", hour, min, sec, msec);
	}
	return (dtime_t)(((((hour * 60) + min) * 60) + sec) * 1000 + msec);
}

static void number_to_time(dtime_t n, int32_t &hour, int32_t &min, int32_t &sec, int32_t &msec) {
	int h, m, s, ms;

	h = n / 3600000;
	n -= h * 3600000;
	m = n / 60000;
	n -= m * 60000;
	s = n / 1000;
	n -= s * 1000;
	ms = n;

	hour = h;
	min = m;
	sec = s;
	msec = ms;
}

// TODO this is duplicated in date.cpp
static bool ParseDoubleDigit2(const char *buf, idx_t len, idx_t &pos, int32_t &result) {
	if (pos < len && StringUtil::CharacterIsDigit(buf[pos])) {
		result = buf[pos++] - '0';
		if (pos < len && StringUtil::CharacterIsDigit(buf[pos])) {
			result = (buf[pos++] - '0') + result * 10;
		}
		return true;
	}
	return false;
}

bool Time::TryConvertTime(const char *buf, idx_t len, idx_t &pos, dtime_t &result, bool strict) {
	int32_t hour = -1, min = -1, sec = -1, msec = -1;
	pos = 0;

	if (len == 0) {
		return false;
	}

	int sep;

	// skip leading spaces
	while (pos < len && StringUtil::CharacterIsSpace(buf[pos])) {
		pos++;
	}

	if (pos >= len) {
		return false;
	}

	if (!StringUtil::CharacterIsDigit(buf[pos])) {
		return false;
	}

	if (!ParseDoubleDigit2(buf, len, pos, hour)) {
		return false;
	}
	if (hour < 0 || hour > 24) {
		return false;
	}

	if (pos >= len) {
		return false;
	}

	// fetch the separator
	sep = buf[pos++];
	if (sep != ':') {
		// invalid separator
		return false;
	}

	if (!ParseDoubleDigit2(buf, len, pos, min)) {
		return false;
	}
	if (min < 0 || min > 60) {
		return false;
	}

	if (pos >= len) {
		return false;
	}

	if (buf[pos++] != sep) {
		return false;
	}

	if (!ParseDoubleDigit2(buf, len, pos, sec)) {
		return false;
	}
	if (sec < 0 || sec > 60) {
		return false;
	}

	msec = 0;
	if (pos < len && buf[pos++] == '.') { // we expect some milliseconds
		uint8_t mult = 100;
		for (; pos < len && StringUtil::CharacterIsDigit(buf[pos]); pos++, mult /= 10) {
			if (mult > 0) {
				msec += (buf[pos] - '0') * mult;
			}
		}
	}

	// in strict mode, check remaining string for non-space characters
	if (strict) {
		// skip trailing spaces
		while (pos < len && StringUtil::CharacterIsSpace(buf[pos])) {
			pos++;
		}
		// check position. if end was not reached, non-space chars remaining
		if (pos < len) {
			return false;
		}
	}

	result = Time::FromTime(hour, min, sec, msec);
	return true;
}

dtime_t Time::FromCString(const char *buf, idx_t len, bool strict) {
	dtime_t result;
	idx_t pos;
	if (!TryConvertTime(buf, len, pos, result, strict)) {
		// last chance, check if we can parse as timestamp
		if (!strict) {
			return Timestamp::GetTime(Timestamp::FromString(buf));
		}
		throw ConversionException("time field value out of range: \"%s\", "
		                          "expected format is ([YYY-MM-DD ]HH:MM:SS[.MS])",
		                          string(buf, len));
	}
	return result;
}

dtime_t Time::FromString(string str, bool strict) {
	return Time::FromCString(str.c_str(), str.size(), strict);
}

string Time::ToString(dtime_t time) {
	int32_t hour, min, sec, msec;
	number_to_time(time, hour, min, sec, msec);

	if (msec > 0) {
		return StringUtil::Format("%02d:%02d:%02d.%03d", hour, min, sec, msec);
	} else {
		return StringUtil::Format("%02d:%02d:%02d", hour, min, sec);
	}
}

string Time::Format(int32_t hour, int32_t minute, int32_t second, int32_t milisecond) {
	return ToString(Time::FromTime(hour, minute, second, milisecond));
}

dtime_t Time::FromTime(int32_t hour, int32_t minute, int32_t second, int32_t milisecond) {
	return time_to_number(hour, minute, second, milisecond);
}

bool Time::IsValidTime(int32_t hour, int32_t minute, int32_t second, int32_t milisecond) {
	return DD_TIME(hour, minute, second, milisecond);
}

void Time::Convert(dtime_t time, int32_t &out_hour, int32_t &out_min, int32_t &out_sec, int32_t &out_msec) {
	number_to_time(time, out_hour, out_min, out_sec, out_msec);
}

} // namespace duckdb

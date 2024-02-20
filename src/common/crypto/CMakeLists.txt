add_library_unity(duckdb_common_crypto OBJECT md5.cpp)
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

set(ALL_OBJECT_FILES
    ${ALL_OBJECT_FILES} $<TARGET_OBJECTS:duckdb_common_crypto>
    PARENT_SCOPE)

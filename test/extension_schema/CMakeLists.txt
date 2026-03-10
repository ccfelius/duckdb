add_library_unity(test_extension_schema OBJECT overload_extension_functions.cpp)

set(ALL_OBJECT_FILES
    ${ALL_OBJECT_FILES} $<TARGET_OBJECTS:test_extension_schema>
    PARENT_SCOPE)

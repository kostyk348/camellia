cmake_minimum_required(VERSION 3.10)
project(camellia C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2 -Wall -Wextra")

# Core library
add_library(camellia_static STATIC src/camellia.c)
add_library(camellia_shared SHARED src/camellia.c)
target_include_directories(camellia_static PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(camellia_shared PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
set_target_properties(camellia_static PROPERTIES OUTPUT_NAME camellia)
set_target_properties(camellia_shared PROPERTIES OUTPUT_NAME camellia)

# Self-test
add_executable(test_camellia tests/test_camellia.c)
target_link_libraries(test_camellia camellia_static)
add_test(NAME selftest COMMAND test_camellia)

# CLI
add_executable(camellia-cli tools/camellia-cli.c)
target_link_libraries(camellia-cli camellia_static)

# Benchmark (OpenSSL optional)
find_package(OpenSSL)
if(OpenSSL_FOUND)
    add_executable(bench tools/bench.c)
    target_link_libraries(bench camellia_static OpenSSL::Crypto)
    target_compile_definitions(bench PRIVATE HAVE_OPENSSL)
else()
    add_executable(bench tools/bench.c)
    target_link_libraries(bench camellia_static)
endif()

enable_testing()

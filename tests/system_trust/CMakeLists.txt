# SPDX-License-Identifier: GPL-3.0-or-later
# Standalone tests: only CMake, a C compiler and OpenSSL, no PKCS#11/GTK/QPDF.
cmake_minimum_required(VERSION 3.16)
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    project(libssig_system_trust_tests LANGUAGES C)
    set(CMAKE_C_STANDARD 99)
    set(CMAKE_C_STANDARD_REQUIRED ON)
    set(CMAKE_C_EXTENSIONS OFF)
    enable_testing()
    find_package(OpenSSL 3.5 REQUIRED COMPONENTS Crypto)
endif()
get_filename_component(TRUST_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
set(TRUST_SOURCES "${TRUST_SOURCE_DIR}/libssig/trust_system.c"
    "${TRUST_SOURCE_DIR}/libssig/trust.c" "${TRUST_SOURCE_DIR}/libssig/trust_fallback.c")
add_executable(system_trust_test system_trust_test.c ${TRUST_SOURCES})
target_include_directories(system_trust_test PRIVATE "${TRUST_SOURCE_DIR}")
target_link_libraries(system_trust_test PRIVATE OpenSSL::Crypto)
target_compile_definitions(system_trust_test PRIVATE LIBSSIG_TEST_NATIVE_TRUST)
target_compile_options(system_trust_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME system_trust COMMAND system_trust_test)
set_tests_properties(system_trust PROPERTIES ENVIRONMENT
    "SSL_CERT_FILE=${CMAKE_CURRENT_BINARY_DIR}/missing-ca.pem;SSL_CERT_DIR=${CMAKE_CURRENT_BINARY_DIR}/missing-certs")
if(WIN32 OR APPLE)
    add_executable(system_trust_os_test system_trust_os_test.c ${TRUST_SOURCES}
        "${TRUST_SOURCE_DIR}/libssig/trust_system_windows.c"
        "${TRUST_SOURCE_DIR}/libssig/trust_system_macos.c")
    target_include_directories(system_trust_os_test PRIVATE "${TRUST_SOURCE_DIR}")
    target_link_libraries(system_trust_os_test PRIVATE OpenSSL::Crypto)
    target_compile_options(system_trust_os_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
    if(WIN32)
        target_link_libraries(system_trust_os_test PRIVATE crypt32)
    else()
        find_library(TRUST_SECURITY_FRAMEWORK Security REQUIRED)
        find_library(TRUST_COREFOUNDATION_FRAMEWORK CoreFoundation REQUIRED)
        target_link_libraries(system_trust_os_test PRIVATE
            "${TRUST_SECURITY_FRAMEWORK}" "${TRUST_COREFOUNDATION_FRAMEWORK}")
    endif()
    add_test(NAME system_trust_os COMMAND system_trust_os_test)
    set_tests_properties(system_trust_os PROPERTIES ENVIRONMENT
        "SSL_CERT_FILE=${CMAKE_CURRENT_BINARY_DIR}/missing-ca.pem;SSL_CERT_DIR=${CMAKE_CURRENT_BINARY_DIR}/missing-certs")
endif()

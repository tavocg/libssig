# This file is part of libssig.
# Copyright (C) 2026 Gustavo Calvo <tavo@tavo.cr>
# SPDX-License-Identifier: GPL-3.0-or-later
#
# See libssig/libssig.c for the full copyright and warranty notice.
# See LICENSE in the project root for the GNU General Public License.

add_executable(noop_test noop_test.c)
target_link_libraries(noop_test PRIVATE libssig::ssig)
target_compile_options(noop_test PRIVATE -Wall -Wextra -Wpedantic -Werror)

add_test(NAME noop COMMAND noop_test)

# Manual integration check using the locally configured PKCS#11 modules.
add_executable(tokens_list tokens_list.c)
target_link_libraries(tokens_list PRIVATE libssig::ssig PkgConfig::P11_KIT)
target_compile_options(tokens_list PRIVATE -Wall -Wextra -Wpedantic -Werror)

add_executable(session_test session_test.c)
target_link_libraries(session_test PRIVATE libssig::ssig PkgConfig::P11_KIT)
target_compile_options(session_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME session COMMAND session_test)

add_executable(login_test login_test.c)
target_link_libraries(login_test PRIVATE libssig::ssig PkgConfig::P11_KIT)
target_compile_options(login_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME login COMMAND login_test)

# Manual integration check: prompts for a real token's PIN.
add_executable(token_login token_login.c)
target_link_libraries(token_login PRIVATE libssig::ssig PkgConfig::P11_KIT OpenSSL::Crypto)
target_compile_options(token_login PRIVATE -Wall -Wextra -Wpedantic -Werror)

add_executable(certificates_test certificates_test.c)
target_link_libraries(certificates_test PRIVATE libssig::ssig PkgConfig::P11_KIT)
target_compile_options(certificates_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME certificates COMMAND certificates_test)

set_target_properties(tokens_list PROPERTIES OUTPUT_NAME list-tokens)
set_target_properties(token_login PROPERTIES OUTPUT_NAME login-token)

add_executable(version_test version_test.c)
target_link_libraries(version_test PRIVATE libssig::ssig)
target_compile_options(version_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME version COMMAND version_test)

# Compile the implementation with a simulated module loader for lifecycle checks.
add_executable(context_test context_test.c
    ../libssig/context.c ../libssig/tokens.c
    ../libssig/certificates.c ../libssig/certificate_metadata.c ../libssig/session.c)
target_include_directories(context_test PRIVATE ${PROJECT_SOURCE_DIR})
target_link_libraries(context_test PRIVATE PkgConfig::P11_KIT OpenSSL::Crypto)
target_compile_options(context_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME context COMMAND context_test)

add_executable(token_flags_test token_flags_test.c)
target_link_libraries(token_flags_test PRIVATE libssig::ssig PkgConfig::P11_KIT)
target_compile_options(token_flags_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME token_flags COMMAND token_flags_test)

add_executable(sign_test sign_test.c)
target_link_libraries(sign_test PRIVATE libssig::ssig PkgConfig::P11_KIT OpenSSL::Crypto)
target_compile_options(sign_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME sign COMMAND sign_test)

# Manual integration check: signs a fixed message with a real token and verifies it.
add_executable(token_sign token_sign.c)
target_link_libraries(token_sign PRIVATE libssig::ssig PkgConfig::P11_KIT OpenSSL::Crypto)
target_compile_options(token_sign PRIVATE -Wall -Wextra -Wpedantic -Werror)
set_target_properties(token_sign PROPERTIES OUTPUT_NAME sign-token)

add_executable(certificate_metadata_test certificate_metadata_test.c)
target_link_libraries(certificate_metadata_test PRIVATE libssig::ssig PkgConfig::P11_KIT OpenSSL::Crypto)
target_compile_options(certificate_metadata_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME certificate_metadata COMMAND certificate_metadata_test)

# Manual CMS/CAdES signing using a real token.
add_executable(token_sign_file token_sign.c)
target_compile_definitions(token_sign_file PRIVATE LIBSSIG_CMS_FILE=1)
target_link_libraries(token_sign_file PRIVATE libssig::ssig PkgConfig::P11_KIT OpenSSL::Crypto)
target_compile_options(token_sign_file PRIVATE -Wall -Wextra -Wpedantic -Werror)
set_target_properties(token_sign_file PROPERTIES OUTPUT_NAME sign-file)

find_program(OPENSSL_EXECUTABLE openssl)
if(OPENSSL_EXECUTABLE)
    add_test(NAME cms_openssl
        COMMAND ${CMAKE_COMMAND}
            "-DSIGN_TEST=$<TARGET_FILE:sign_test>"
            "-DOPENSSL=${OPENSSL_EXECUTABLE}"
            "-DFIXTURES=${CMAKE_CURRENT_BINARY_DIR}/cms-fixtures"
            -P ${CMAKE_CURRENT_SOURCE_DIR}/cms_verify.cmake)
endif()

# Public-header consumer: no PKCS#11/OpenSSL include paths or internal headers.
add_executable(public_sign_test public_sign_test.c)
target_link_libraries(public_sign_test PRIVATE libssig::ssig)
target_compile_options(public_sign_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME public_sign COMMAND public_sign_test)

add_executable(mime_test mime_test.c)
target_link_libraries(mime_test PRIVATE libssig::ssig PkgConfig::P11_KIT)
target_compile_options(mime_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME mime COMMAND mime_test)
add_test(NAME mime_missing_database COMMAND mime_test --missing-db)
add_test(NAME sign_mime_override COMMAND sign_test --mime-override-only)
set_tests_properties(mime_missing_database sign_mime_override PROPERTIES
    ENVIRONMENT "MAGIC=${CMAKE_CURRENT_BINARY_DIR}/missing-magic-database")

add_executable(verify_file verify_file.c)
target_link_libraries(verify_file PRIVATE libssig::ssig)
target_compile_options(verify_file PRIVATE -Wall -Wextra -Wpedantic -Werror)
set_target_properties(verify_file PROPERTIES OUTPUT_NAME verify-file)

add_executable(verify_test verify_test.c)
target_link_libraries(verify_test PRIVATE libssig::ssig OpenSSL::Crypto)
target_compile_options(verify_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME verify COMMAND verify_test)

add_executable(verify_trust_test verify_trust_test.c)
target_link_libraries(verify_trust_test PRIVATE libssig::ssig OpenSSL::Crypto)
target_compile_options(verify_trust_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME verify_trust COMMAND verify_trust_test)
add_test(NAME verify_cli
    COMMAND ${CMAKE_COMMAND}
        "-DTRUST_TEST=$<TARGET_FILE:verify_trust_test>"
        "-DVERIFY_FILE=$<TARGET_FILE:verify_file>"
        "-DOPENSSL=${OPENSSL_EXECUTABLE}"
        "-DFIXTURES=${CMAKE_CURRENT_BINARY_DIR}/verify-fixtures"
        -P ${CMAKE_CURRENT_SOURCE_DIR}/verify_cli.cmake)

add_executable(timestamp_test timestamp_test.c)
target_link_libraries(timestamp_test PRIVATE libssig::ssig OpenSSL::Crypto)
target_compile_options(timestamp_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME timestamp
    COMMAND ${CMAKE_COMMAND}
        "-DSIGN_TEST=$<TARGET_FILE:sign_test>"
        "-DTIMESTAMP_TEST=$<TARGET_FILE:timestamp_test>"
        "-DPERSISTED_TEST=$<TARGET_FILE:persisted_timestamp_test>"
        "-DVERIFY_FILE=$<TARGET_FILE:verify_file>"
        "-DOPENSSL=${OPENSSL_EXECUTABLE}"
        "-DFIXTURES=${CMAKE_CURRENT_BINARY_DIR}/timestamp-fixtures"
        -P ${CMAKE_CURRENT_SOURCE_DIR}/timestamp_verify.cmake)

add_executable(persisted_timestamp_test persisted_timestamp_test.c)
target_link_libraries(persisted_timestamp_test PRIVATE libssig::ssig OpenSSL::Crypto)
target_compile_options(persisted_timestamp_test PRIVATE -Wall -Wextra -Wpedantic -Werror)

add_executable(ocsp_test ocsp_test.c)
target_link_libraries(ocsp_test PRIVATE libssig::ssig OpenSSL::Crypto)
target_compile_options(ocsp_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME ocsp COMMAND ocsp_test)

add_executable(ocsp_file ocsp_file.c)
target_link_libraries(ocsp_file PRIVATE libssig::ssig)
target_compile_options(ocsp_file PRIVATE -Wall -Wextra -Wpedantic -Werror)
set_target_properties(ocsp_file PROPERTIES OUTPUT_NAME ocsp-file)
add_test(NAME ocsp_cli
    COMMAND ${CMAKE_COMMAND}
        "-DOCSP_TEST=$<TARGET_FILE:ocsp_test>"
        "-DOCSP_FILE=$<TARGET_FILE:ocsp_file>"
        "-DOPENSSL=${OPENSSL_EXECUTABLE}"
        "-DFIXTURES=${CMAKE_CURRENT_BINARY_DIR}/ocsp-fixtures"
        -P ${CMAKE_CURRENT_SOURCE_DIR}/ocsp_cli.cmake)

add_executable(timestamp_file timestamp_file.c)
target_link_libraries(timestamp_file PRIVATE libssig::ssig)
target_compile_options(timestamp_file PRIVATE -Wall -Wextra -Wpedantic -Werror)
set_target_properties(timestamp_file PROPERTIES OUTPUT_NAME timestamp-file)

option(LIBSSIG_TEST_TSA_SINPE "Contact the real Costa Rican TSA (network test)" OFF)
set(LIBSSIG_TSA_SINPE_CA_FILE "" CACHE FILEPATH "Trusted TSA-SINPE roots (PEM/DER)")
set(LIBSSIG_TSA_SINPE_INTERMEDIATES_FILE "" CACHE FILEPATH "Untrusted TSA intermediates")
set(LIBSSIG_TSA_SINPE_URL "http://tsa.sinpe.fi.cr/tsaHttp/" CACHE STRING "TSA-SINPE RFC 3161 URL")
if(LIBSSIG_TEST_TSA_SINPE)
    if(NOT EXISTS "${LIBSSIG_TSA_SINPE_CA_FILE}")
        message(FATAL_ERROR "Provide LIBSSIG_TSA_SINPE_CA_FILE from a trusted official source")
    endif()
    find_program(CURL_EXECUTABLE curl REQUIRED)
    add_test(NAME tsa_sinpe
        COMMAND ${CMAKE_COMMAND}
            "-DSIGN_TEST=$<TARGET_FILE:sign_test>"
            "-DTIMESTAMP_FILE=$<TARGET_FILE:timestamp_file>"
            "-DVERIFY_FILE=$<TARGET_FILE:verify_file>"
            "-DCURL=${CURL_EXECUTABLE}"
            "-DURL=${LIBSSIG_TSA_SINPE_URL}"
            "-DROOTS=${LIBSSIG_TSA_SINPE_CA_FILE}"
            "-DINTERMEDIATES=${LIBSSIG_TSA_SINPE_INTERMEDIATES_FILE}"
            "-DFIXTURES=${CMAKE_CURRENT_BINARY_DIR}/tsa-sinpe-fixtures"
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tsa_sinpe.cmake)
    set_tests_properties(tsa_sinpe PROPERTIES LABELS "network;manual" TIMEOUT 90 RUN_SERIAL TRUE)
endif()

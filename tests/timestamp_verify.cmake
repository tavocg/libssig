# SPDX-License-Identifier: GPL-3.0-or-later
file(MAKE_DIRECTORY "${FIXTURES}")
execute_process(COMMAND "${SIGN_TEST}" "${FIXTURES}" RESULT_VARIABLE result)
if(NOT result EQUAL 0)
    message(FATAL_ERROR "Could not generate CAdES timestamp inputs")
endif()
execute_process(COMMAND "${TIMESTAMP_TEST}" "${FIXTURES}" RESULT_VARIABLE result)
if(NOT result EQUAL 0)
    message(FATAL_ERROR "Timestamp request/response checks failed")
endif()
if(OPENSSL)
    execute_process(COMMAND "${OPENSSL}" ts -verify
        -queryfile "${FIXTURES}/timestamp.tsq" -in "${FIXTURES}/timestamp.tsr"
        -CAfile "${FIXTURES}/tsa-root.pem"
        RESULT_VARIABLE result ERROR_VARIABLE error)
    if(NOT result EQUAL 0)
        message(FATAL_ERROR "OpenSSL rejected the RFC 3161 response: ${error}")
    endif()
    execute_process(COMMAND "${OPENSSL}" cms -verify -binary -inform DER
        -in "${FIXTURES}/timestamped.p7m" -noverify
        -out "${FIXTURES}/timestamped-content.bin"
        RESULT_VARIABLE result ERROR_VARIABLE error)
    if(NOT result EQUAL 0)
        message(FATAL_ERROR "Timestamp insertion broke the original signature: ${error}")
    endif()
    file(SHA256 "${FIXTURES}/input.bin" original_hash)
    file(SHA256 "${FIXTURES}/timestamped-content.bin" stamped_hash)
    if(NOT original_hash STREQUAL stamped_hash)
        message(FATAL_ERROR "Timestamp insertion changed the document")
    endif()
endif()

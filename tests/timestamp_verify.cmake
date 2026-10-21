# SPDX-License-Identifier: GPL-3.0-or-later
# Nix OpenSSL gives this variable precedence over SSL_CERT_FILE.
unset(ENV{NIX_SSL_CERT_FILE})
file(MAKE_DIRECTORY "${FIXTURES}")
execute_process(COMMAND "${SIGN_TEST}" "${FIXTURES}" RESULT_VARIABLE result)
if(NOT result EQUAL 0)
    message(FATAL_ERROR "Could not generate CAdES timestamp inputs")
endif()
execute_process(COMMAND "${TIMESTAMP_TEST}" "${FIXTURES}" RESULT_VARIABLE result)
if(NOT result EQUAL 0)
    message(FATAL_ERROR "Timestamp request/response checks failed")
endif()
execute_process(COMMAND "${PERSISTED_TEST}" "${FIXTURES}" RESULT_VARIABLE result)
if(NOT result EQUAL 0)
    message(FATAL_ERROR "Persisted timestamp verification failed")
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

# CLI verification uses only the persisted container: no TSQ or TSR input.
function(check_timestamp_command expected)
    execute_process(COMMAND "${VERIFY_FILE}" ${ARGN}
        RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error)
    if(expected STREQUAL "success")
        if(NOT result EQUAL 0 OR NOT output MATCHES "Sello: válido" OR
           NOT output MATCHES "Confianza TSA: válida")
            message(FATAL_ERROR "Expected trusted timestamp: ${ARGN}\n${output}${error}")
        endif()
    elseif(result EQUAL 0 OR NOT output MATCHES "Firma criptográfica válida")
        message(FATAL_ERROR "Expected preserved document result and failure: ${ARGN}\n${output}${error}")
    endif()
endfunction()
check_timestamp_command(success --require-timestamp
    --tsa-ca-file "${FIXTURES}/tsa-root.pem" "${FIXTURES}/timestamped.p7m")
check_timestamp_command(success --require-timestamp
    --ca-file "${FIXTURES}/cades-0-0.pem"
    --tsa-ca-file "${FIXTURES}/tsa-root.pem" "${FIXTURES}/timestamped.p7m")
check_timestamp_command(failure --tsa-ca-file "${FIXTURES}/cades-0-0.pem"
    "${FIXTURES}/timestamped.p7m")
check_timestamp_command(failure --require-timestamp "${FIXTURES}/attached-cades-0-0.p7m")
check_timestamp_command(failure --tsa-ca-file "${FIXTURES}/tsa-root.pem"
    "${FIXTURES}/timestamp-expired.p7m")
set(ENV{SSL_CERT_FILE} "${FIXTURES}/tsa-root.pem")
set(ENV{SSL_CERT_DIR} "${FIXTURES}/no-system-directory")
check_timestamp_command(success --tsa-system-trust --require-timestamp
    "${FIXTURES}/timestamped.p7m")

# SPDX-License-Identifier: GPL-3.0-or-later
file(MAKE_DIRECTORY "${FIXTURES}")
execute_process(COMMAND "${TRUST_TEST}" "${FIXTURES}" RESULT_VARIABLE result)
if(NOT result EQUAL 0)
    message(FATAL_ERROR "Could not generate verification chain fixtures")
endif()

set(ENV{SSL_CERT_FILE} "${FIXTURES}/root.pem")
set(ENV{SSL_CERT_DIR} "${FIXTURES}/no-system-directory")
file(WRITE "${FIXTURES}/invalid.pem" "not a certificate\n")
file(WRITE "${FIXTURES}/empty.pem" "")

function(check_command expected)
    execute_process(COMMAND "${VERIFY_FILE}" ${ARGN}
        RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error)
    if(expected STREQUAL "success")
        if(NOT result EQUAL 0 OR NOT output MATCHES "Confianza: válida")
            message(FATAL_ERROR "Verification should succeed: ${ARGN}\n${output}${error}")
        endif()
    elseif(result EQUAL 0)
        message(FATAL_ERROR "Verification should fail: ${ARGN}\n${output}${error}")
    endif()
endfunction()

check_command(success --ca-file "${FIXTURES}/root.pem"
    --intermediates "${FIXTURES}/intermediate.pem" "${FIXTURES}/signed.p7m")
check_command(success --system-trust --intermediates "${FIXTURES}/intermediate.pem"
    --ca-file "${FIXTURES}/other.pem" "${FIXTURES}/signed.p7m")
check_command(success --intermediates "${FIXTURES}/intermediate.pem"
    --system-trust "${FIXTURES}/signed.p7m")
check_command(failure --ca-file "${FIXTURES}/other.pem"
    --intermediates "${FIXTURES}/intermediate.pem" "${FIXTURES}/signed.p7m")
check_command(failure --ca-file "${FIXTURES}/root.pem" "${FIXTURES}/signed.p7m")
check_command(failure --ca-file "${FIXTURES}/invalid.pem" "${FIXTURES}/signed.p7m")
check_command(failure --ca-file "${FIXTURES}/empty.pem" "${FIXTURES}/signed.p7m")
check_command(failure --ca-file "${FIXTURES}/missing.pem" "${FIXTURES}/signed.p7m")
check_command(failure --intermediates "${FIXTURES}/intermediate.pem" "${FIXTURES}/signed.p7m")
check_command(failure --ca-file)
check_command(failure --ca-file --system-trust "${FIXTURES}/signed.p7m")
check_command(failure --ca-file "${FIXTURES}/root.pem" --ca-file "${FIXTURES}/other.pem"
    "${FIXTURES}/signed.p7m")
check_command(failure --unknown "${FIXTURES}/signed.p7m")

# Compare the same custom chain against the independent OpenSSL command.
if(OPENSSL)
    execute_process(COMMAND "${OPENSSL}" cms -verify -binary -inform DER
        -in "${FIXTURES}/signed.p7m" -CAfile "${FIXTURES}/root.pem"
        -certfile "${FIXTURES}/intermediate.pem" -purpose any
        -out "${FIXTURES}/verified.txt"
        RESULT_VARIABLE result ERROR_VARIABLE error)
    if(NOT result EQUAL 0)
        message(FATAL_ERROR "OpenSSL rejected the custom chain: ${error}")
    endif()
    file(READ "${FIXTURES}/verified.txt" content)
    if(NOT content STREQUAL "Document")
        message(FATAL_ERROR "OpenSSL verified content differs from the original")
    endif()
endif()

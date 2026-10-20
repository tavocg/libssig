# SPDX-License-Identifier: GPL-3.0-or-later
file(MAKE_DIRECTORY "${FIXTURES}")
execute_process(COMMAND "${OCSP_TEST}" "${FIXTURES}" RESULT_VARIABLE result)
if(NOT result EQUAL 0)
    message(FATAL_ERROR "OCSP fixture generation failed")
endif()

# Remove only this script's previous generated request before the O_EXCL check.
file(REMOVE "${FIXTURES}/new-request.der")
execute_process(COMMAND "${OCSP_FILE}" request "${FIXTURES}/cert.pem"
    "${FIXTURES}/issuer.pem" "${FIXTURES}/new-request.der"
    RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error)
if(NOT result EQUAL 0 OR NOT output MATCHES "URL: http://ocsp.example/status")
    message(FATAL_ERROR "OCSP CLI request failed: ${output}${error}")
endif()
file(SHA256 "${FIXTURES}/new-request.der" before)
execute_process(COMMAND "${OCSP_FILE}" request "${FIXTURES}/cert.pem"
    "${FIXTURES}/issuer.pem" "${FIXTURES}/new-request.der"
    RESULT_VARIABLE result OUTPUT_QUIET ERROR_QUIET)
file(SHA256 "${FIXTURES}/new-request.der" after)
if(result EQUAL 0 OR NOT before STREQUAL after)
    message(FATAL_ERROR "OCSP CLI overwrote an existing output")
endif()

function(verify_response expected authority)
    execute_process(COMMAND "${OCSP_FILE}" verify "${FIXTURES}/cert.pem"
        "${FIXTURES}/issuer.pem" "${FIXTURES}/request.der"
        "${FIXTURES}/response.der" "${authority}"
        RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error)
    if(expected STREQUAL "success")
        if(NOT result EQUAL 0 OR NOT output MATCHES "OCSP: no revocado")
            message(FATAL_ERROR "OCSP CLI should accept response: ${output}${error}")
        endif()
    elseif(result EQUAL 0 OR NOT output MATCHES "OCSP: consulta fallida")
        message(FATAL_ERROR "OCSP CLI should reject response: ${output}${error}")
    endif()
endfunction()
verify_response(success "${FIXTURES}/issuer.pem")
verify_response(failure "${FIXTURES}/other.pem")
set(ENV{SSL_CERT_FILE} "${FIXTURES}/issuer.pem")
set(ENV{SSL_CERT_DIR} "${FIXTURES}/no-system-directory")
verify_response(success --system-trust)

if(OPENSSL)
    execute_process(COMMAND "${OPENSSL}" ocsp -reqin "${FIXTURES}/request.der"
        -respin "${FIXTURES}/response.der" -CAfile "${FIXTURES}/issuer.pem"
        RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error)
    if(NOT result EQUAL 0 OR NOT error MATCHES "Response verify OK")
        message(FATAL_ERROR "OpenSSL rejected the OCSP response: ${output}${error}")
    endif()
endif()

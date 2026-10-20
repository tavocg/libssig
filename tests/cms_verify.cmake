# SPDX-License-Identifier: GPL-3.0-or-later
file(MAKE_DIRECTORY "${FIXTURES}")
execute_process(COMMAND "${SIGN_TEST}" "${FIXTURES}" RESULT_VARIABLE result)
if(NOT result EQUAL 0)
    message(FATAL_ERROR "Could not generate token-backed CMS fixtures: ${result}")
endif()

foreach(algo RANGE 0 2)
    foreach(hash RANGE 0 2)
        set(signature "${FIXTURES}/cms-${algo}-${hash}.p7s")
        execute_process(COMMAND "${OPENSSL}" cms -verify -binary -inform DER
            -in "${signature}" -content "${FIXTURES}/input.bin" -noverify
            -out "${FIXTURES}/verified.bin"
            RESULT_VARIABLE result ERROR_VARIABLE error)
        if(NOT result EQUAL 0)
            message(FATAL_ERROR "OpenSSL rejected ${signature}: ${error}")
        endif()
        file(SHA256 "${FIXTURES}/input.bin" input_hash)
        file(SHA256 "${FIXTURES}/verified.bin" output_hash)
        if(NOT input_hash STREQUAL output_hash)
            message(FATAL_ERROR "Verified content differs from the original")
        endif()
        execute_process(COMMAND "${OPENSSL}" cms -verify -binary -inform DER
            -in "${signature}" -content "${FIXTURES}/altered.bin" -noverify
            -out "${FIXTURES}/rejected.bin"
            RESULT_VARIABLE result ERROR_VARIABLE error)
        if(result EQUAL 0)
            message(FATAL_ERROR "OpenSSL accepted altered content for ${signature}")
        endif()
    endforeach()
endforeach()

foreach(algo RANGE 0 2)
    foreach(hash RANGE 0 2)
        set(signature "${FIXTURES}/cades-${algo}-${hash}.p7s")
        set(certificate "${FIXTURES}/cades-${algo}-${hash}.pem")
        execute_process(COMMAND "${OPENSSL}" cms -verify -cades -binary -inform DER
            -in "${signature}" -content "${FIXTURES}/input.bin"
            -CAfile "${certificate}" -purpose any -out "${FIXTURES}/cades-verified.bin"
            RESULT_VARIABLE result ERROR_VARIABLE error)
        if(NOT result EQUAL 0)
            message(FATAL_ERROR "OpenSSL rejected CAdES ${signature}: ${error}")
        endif()
        file(SHA256 "${FIXTURES}/input.bin" input_hash)
        file(SHA256 "${FIXTURES}/cades-verified.bin" output_hash)
        if(NOT input_hash STREQUAL output_hash)
            message(FATAL_ERROR "CAdES verified content differs from the original")
        endif()
        execute_process(COMMAND "${OPENSSL}" cms -verify -cades -binary -inform DER
            -in "${signature}" -content "${FIXTURES}/altered.bin"
            -CAfile "${certificate}" -purpose any -out "${FIXTURES}/cades-rejected.bin"
            RESULT_VARIABLE result ERROR_VARIABLE error)
        if(result EQUAL 0)
            message(FATAL_ERROR "OpenSSL accepted altered content for CAdES ${signature}")
        endif()
    endforeach()
endforeach()

# The signature itself is valid, but its ESS certificate hash was deliberately
# changed and re-signed. Ordinary CMS verification passes; CAdES must reject it.
execute_process(COMMAND "${OPENSSL}" cms -verify -binary -inform DER
    -in "${FIXTURES}/cades-bad-cert.p7s" -content "${FIXTURES}/input.bin"
    -noverify -out "${FIXTURES}/bad-cert-content.bin"
    RESULT_VARIABLE result ERROR_VARIABLE error)
if(NOT result EQUAL 0)
    message(FATAL_ERROR "Invalid negative-test setup: CMS signature failed: ${error}")
endif()
execute_process(COMMAND "${OPENSSL}" cms -verify -cades -binary -inform DER
    -in "${FIXTURES}/cades-bad-cert.p7s" -content "${FIXTURES}/input.bin"
    -CAfile "${FIXTURES}/cades-0-0.pem" -purpose any
    -out "${FIXTURES}/bad-cert-rejected.bin"
    RESULT_VARIABLE result ERROR_VARIABLE error)
if(result EQUAL 0)
    message(FATAL_ERROR "OpenSSL accepted an incorrect ESS certificate hash")
endif()

# Attached containers generated through the public API need no external content.
foreach(format cms cades)
    foreach(algo RANGE 0 2)
        foreach(hash RANGE 0 2)
            set(signature "${FIXTURES}/attached-${format}-${algo}-${hash}.p7m")
            execute_process(COMMAND "${OPENSSL}" cms -verify -binary -inform DER
                -in "${signature}" -noverify -out "${FIXTURES}/attached-verified.bin"
                RESULT_VARIABLE result ERROR_VARIABLE error)
            if(NOT result EQUAL 0)
                message(FATAL_ERROR "OpenSSL rejected attached ${signature}: ${error}")
            endif()
            file(SHA256 "${FIXTURES}/input.bin" input_hash)
            file(SHA256 "${FIXTURES}/attached-verified.bin" output_hash)
            if(NOT input_hash STREQUAL output_hash)
                message(FATAL_ERROR "Attached content differs from the original")
            endif()
        endforeach()
    endforeach()
endforeach()

# SPDX-License-Identifier: GPL-3.0-or-later
# Each run keeps its own request/reply for inspection and never overwrites them.
string(RANDOM LENGTH 16 ALPHABET 0123456789abcdef run_id)
set(FIXTURES "${FIXTURES}/${run_id}")
file(MAKE_DIRECTORY "${FIXTURES}")
message(STATUS "TSA artifacts: ${FIXTURES}")
function(run_checked)
    execute_process(COMMAND ${ARGV} RESULT_VARIABLE result
        OUTPUT_VARIABLE output ERROR_VARIABLE error)
    if(NOT "${result}" STREQUAL "0")
        message(FATAL_ERROR "Command failed (${result}): ${ARGV}\n${output}${error}")
    endif()
    message(STATUS "${output}${error}")
endfunction()
run_checked("${SIGN_TEST}" "${FIXTURES}")
set(input "${FIXTURES}/attached-cades-0-0.p7m")
set(query "${FIXTURES}/sinpe.tsq")
set(reply "${FIXTURES}/sinpe.tsr")
set(output "${FIXTURES}/timestamped.p7m")
run_checked("${TIMESTAMP_FILE}" request "${input}" "${query}")
# One POST, no retries or redirects. Only a synthetic signature imprint leaves
# the machine; no document, private key, PIN or personal certificate is sent.
run_checked("${CURL}" --fail --silent --show-error
    --proto =http,https --connect-timeout 10 --max-time 45
    --max-filesize 1048576
    --header "Content-Type: application/timestamp-query"
    --header "Accept: application/timestamp-reply"
    --data-binary "@${query}" --output "${reply}" "${URL}")
set(apply_intermediates)
set(verify_intermediates)
if(INTERMEDIATES)
    list(APPEND apply_intermediates "${INTERMEDIATES}")
    list(APPEND verify_intermediates --tsa-intermediates "${INTERMEDIATES}")
endif()
run_checked("${TIMESTAMP_FILE}" apply "${input}" "${query}" "${reply}"
    "${ROOTS}" "${output}" ${apply_intermediates})
run_checked("${VERIFY_FILE}" --require-timestamp --tsa-ca-file "${ROOTS}"
    ${verify_intermediates} "${output}")

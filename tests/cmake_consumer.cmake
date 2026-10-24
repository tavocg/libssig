# SPDX-License-Identifier: GPL-3.0-or-later
# Run against a built library; all generated files stay under WORK_DIR.
function(run)
    execute_process(COMMAND ${ARGV} RESULT_VARIABLE result)
    if(NOT result EQUAL 0)
        message(FATAL_ERROR "Consumer check failed (${result}): ${ARGV}")
    endif()
endfunction()

set(install_config)
if(CONFIG)
    list(APPEND install_config --config "${CONFIG}")
endif()
if(NOT CONFIG)
    set(CONFIG Release)
endif()

if(SHARED)
    set(expected SHARED_LIBRARY)
else()
    set(expected STATIC_LIBRARY)
endif()
set(consumer_source "${SOURCE_DIR}/tests/consumer")
function(check_consumer name)
    set(build "${WORK_DIR}/${name}")
    run("${CMAKE_COMMAND}" -S "${consumer_source}" -B "${build}"
        "-DEXPECTED_TYPE=${expected}" "-DCMAKE_BUILD_TYPE=${CONFIG}" ${ARGN})
    run("${CMAKE_COMMAND}" --build "${build}" --config "${CONFIG}" --parallel 2)
    run("${CMAKE_CTEST_COMMAND}" --test-dir "${build}" -C "${CONFIG}"
        --output-on-failure)
endfunction()

check_consumer(build-tree "-Dlibssig_DIR=${BUILD_DIR}")
# Start from a fresh install and relocate it before finding the package.
file(REMOVE_RECURSE "${WORK_DIR}/stage" "${WORK_DIR}/relocated")
run("${CMAKE_COMMAND}" --install "${BUILD_DIR}" --prefix "${WORK_DIR}/stage"
    ${install_config})
file(RENAME "${WORK_DIR}/stage" "${WORK_DIR}/relocated")
check_consumer(installed "-DCMAKE_PREFIX_PATH=${WORK_DIR}/relocated")
check_consumer(embedded "-DLIBSSIG_SOURCE=${SOURCE_DIR}" "-DBUILD_SHARED_LIBS=${SHARED}")

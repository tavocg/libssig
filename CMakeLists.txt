# This file is part of libssig.
# Copyright (C) 2026 Gustavo Calvo <tavo@tavo.cr>
# SPDX-License-Identifier: GPL-3.0-or-later
#
# See libssig/libssig.c for the full copyright and warranty notice.
# See LICENSE in the project root for the GNU General Public License.

cmake_minimum_required(VERSION 3.16)

project(libssig VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
include(CTest)

find_package(PkgConfig REQUIRED)
find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)
pkg_check_modules(P11_KIT REQUIRED IMPORTED_TARGET p11-kit-1)

file(GLOB_RECURSE LIBSSIG_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/libssig/*.c"
)
list(FILTER LIBSSIG_SOURCES EXCLUDE REGEX "_test\\.c$")

add_library(ssig SHARED ${LIBSSIG_SOURCES})
add_library(libssig::ssig ALIAS ssig)

target_link_libraries(ssig PRIVATE
    PkgConfig::P11_KIT
    OpenSSL::Crypto
)

target_include_directories(ssig PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
)

target_compile_options(ssig PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Werror
)

set_target_properties(ssig PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 0
)

if(BUILD_TESTING)
    add_subdirectory(tests)
endif()

install(TARGETS ssig
    EXPORT libssigTargets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(FILES libssig/libssig.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/libssig
)

install(EXPORT libssigTargets
    FILE libssigTargets.cmake
    NAMESPACE libssig::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/libssig
)

configure_package_config_file(
    cmake/libssigConfig.cmake.in
    "${CMAKE_CURRENT_BINARY_DIR}/libssigConfig.cmake"
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/libssig
)

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/libssigConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/libssigConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/libssigConfigVersion.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/libssig
)

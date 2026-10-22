# This file is part of libssig.
# Copyright (C) 2026 Gustavo Calvo <tavo@tavo.cr>
# SPDX-License-Identifier: GPL-3.0-or-later
#
# See libssig/version.c for the full copyright and warranty notice.
# See LICENSE in the project root for the GNU General Public License.

cmake_minimum_required(VERSION 3.16)

project(libssig VERSION 0.1.1 LANGUAGES C)

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
pkg_check_modules(MAGIC REQUIRED IMPORTED_TARGET libmagic)
pkg_check_modules(JANSSON REQUIRED IMPORTED_TARGET jansson)
pkg_check_modules(XML2 REQUIRED IMPORTED_TARGET libxml-2.0)
find_path(QPDF_INCLUDE_DIR qpdf/qpdf-c.h)
find_library(QPDF_LIBRARY qpdf)
if(NOT QPDF_INCLUDE_DIR OR NOT QPDF_LIBRARY)
    message(FATAL_ERROR "QPDF >= 11 development files are required for PAdES")
endif()

file(GLOB_RECURSE LIBSSIG_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/libssig/*.c"
)
list(FILTER LIBSSIG_SOURCES EXCLUDE REGEX "_test\\.c$")

add_library(ssig SHARED ${LIBSSIG_SOURCES})
add_library(libssig::ssig ALIAS ssig)

target_link_libraries(ssig PRIVATE
    PkgConfig::P11_KIT
    PkgConfig::MAGIC
    PkgConfig::JANSSON
    PkgConfig::XML2
    OpenSSL::Crypto
    ${QPDF_LIBRARY}
)

target_include_directories(ssig PRIVATE ${QPDF_INCLUDE_DIR})

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

install(FILES libssig/libssig.h libssig/types.h libssig/version.h
    libssig/context.h libssig/tokens.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/libssig
)

foreach(feature certificates sign extend verify timestamp ocsp)
    install(FILES libssig/${feature}/${feature}.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/libssig/${feature}
    )
endforeach()

install(EXPORT libssigTargets
    FILE libssigTargets.cmake
    NAMESPACE libssig::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/libssig
)

# Allow sibling projects to consume the local build without installing it.
export(EXPORT libssigTargets
    FILE "${CMAKE_CURRENT_BINARY_DIR}/libssigTargets.cmake"
    NAMESPACE libssig::
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

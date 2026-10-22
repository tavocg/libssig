# This file is part of libssig.
# Copyright (C) 2026 Gustavo Calvo <tavo@tavo.cr>
# SPDX-License-Identifier: GPL-3.0-or-later
#
# See libssig/version.c for the full copyright and warranty notice.
# See LICENSE in the project root for the GNU General Public License.

cmake_minimum_required(VERSION 3.16)

project(libssig VERSION 0.1.3 LANGUAGES C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
include(CTest)

find_package(PkgConfig REQUIRED)
if(WIN32 OR APPLE)
    # Native policy evaluation needs the public verification-purpose accessor.
    find_package(OpenSSL 3.5 REQUIRED COMPONENTS Crypto)
else()
    find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)
endif()
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
include(cmake/OpenSSLCompat.cmake)
libssig_openssl_compat(ssig)

target_link_libraries(ssig PRIVATE
    PkgConfig::P11_KIT
    PkgConfig::MAGIC
    PkgConfig::JANSSON
    PkgConfig::XML2
    OpenSSL::Crypto
    ${QPDF_LIBRARY}
)

option(LIBSSIG_EMBED_MAGIC_DATABASE "Embed a matching libmagic database for portable packages" OFF)
if(LIBSSIG_EMBED_MAGIC_DATABASE)
    find_package(Python3 3.10 REQUIRED COMPONENTS Interpreter)
    find_package(ZLIB REQUIRED)
    pkg_get_variable(MAGIC_PREFIX libmagic prefix)
    find_file(LIBSSIG_MAGIC_DATABASE NAMES magic.mgc
        HINTS "${MAGIC_PREFIX}/share/misc" "${MAGIC_PREFIX}/share/file")
    if(NOT LIBSSIG_MAGIC_DATABASE)
        message(FATAL_ERROR "Set LIBSSIG_MAGIC_DATABASE to the database matching libmagic")
    endif()
    set(MAGIC_EMBED_SOURCE "${CMAKE_CURRENT_BINARY_DIR}/magic_database.c")
    add_custom_command(OUTPUT "${MAGIC_EMBED_SOURCE}"
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/cmake/embed_magic.py"
            "${LIBSSIG_MAGIC_DATABASE}" "${MAGIC_EMBED_SOURCE}"
        DEPENDS "${LIBSSIG_MAGIC_DATABASE}" cmake/embed_magic.py VERBATIM)
    target_sources(ssig PRIVATE "${MAGIC_EMBED_SOURCE}")
    target_compile_definitions(ssig PRIVATE LIBSSIG_EMBED_MAGIC_DATABASE)
    target_link_libraries(ssig PRIVATE ZLIB::ZLIB)
endif()

if(WIN32)
    set_target_properties(ssig PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
    target_link_libraries(ssig PRIVATE crypt32)
elseif(APPLE)
    if(CMAKE_OSX_DEPLOYMENT_TARGET AND CMAKE_OSX_DEPLOYMENT_TARGET VERSION_LESS 10.14)
        message(FATAL_ERROR "Native trust evaluation requires macOS 10.14 or newer")
    endif()
    find_library(SECURITY_FRAMEWORK Security REQUIRED)
    find_library(COREFOUNDATION_FRAMEWORK CoreFoundation REQUIRED)
    target_link_libraries(ssig PRIVATE "${SECURITY_FRAMEWORK}" "${COREFOUNDATION_FRAMEWORK}")
endif()

target_include_directories(ssig SYSTEM PRIVATE ${QPDF_INCLUDE_DIR})

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
    MACOSX_RPATH ON
)

if(BUILD_TESTING)
    add_subdirectory(tests)
endif()

install(TARGETS ssig
    EXPORT libssigTargets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(FILES libssig/libssig.h libssig/types.h libssig/version.h
    libssig/context.h libssig/tokens.h libssig/trust_store.h
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

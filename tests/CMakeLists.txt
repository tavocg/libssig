# This file is part of libssig.
# Copyright (C) 2026 Gustavo Calvo <tavo@tavo.cr>
# SPDX-License-Identifier: GPL-3.0-or-later
#
# See libssig/libssig.c for the full copyright and warranty notice.
# See LICENSE in the project root for the GNU General Public License.

add_executable(noop_test noop_test.c)
target_link_libraries(noop_test PRIVATE libssig::ssig)
target_compile_options(noop_test PRIVATE -Wall -Wextra -Wpedantic -Werror)

add_test(NAME noop COMMAND noop_test)

# Manual integration check using the locally configured PKCS#11 modules.
add_executable(tokens_list tokens_list.c)
target_link_libraries(tokens_list PRIVATE libssig::ssig PkgConfig::P11_KIT)
target_compile_options(tokens_list PRIVATE -Wall -Wextra -Wpedantic -Werror)

add_executable(session_test session_test.c)
target_link_libraries(session_test PRIVATE libssig::ssig PkgConfig::P11_KIT)
target_compile_options(session_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME session COMMAND session_test)

add_executable(login_test login_test.c)
target_link_libraries(login_test PRIVATE libssig::ssig PkgConfig::P11_KIT)
target_compile_options(login_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME login COMMAND login_test)

# Manual integration check: prompts for a real token's PIN.
add_executable(token_login token_login.c)
target_link_libraries(token_login PRIVATE libssig::ssig PkgConfig::P11_KIT OpenSSL::Crypto)
target_compile_options(token_login PRIVATE -Wall -Wextra -Wpedantic -Werror)

add_executable(certificates_test certificates_test.c)
target_link_libraries(certificates_test PRIVATE libssig::ssig PkgConfig::P11_KIT)
target_compile_options(certificates_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME certificates COMMAND certificates_test)

set_target_properties(tokens_list PROPERTIES OUTPUT_NAME list-tokens)
set_target_properties(token_login PROPERTIES OUTPUT_NAME login-token)

add_executable(version_test version_test.c)
target_link_libraries(version_test PRIVATE libssig::ssig)
target_compile_options(version_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME version COMMAND version_test)

# Compile the implementation with a simulated module loader for lifecycle checks.
add_executable(context_test context_test.c
    ../libssig/context.c ../libssig/tokens.c
    ../libssig/certificates.c ../libssig/session.c)
target_include_directories(context_test PRIVATE ${PROJECT_SOURCE_DIR})
target_link_libraries(context_test PRIVATE PkgConfig::P11_KIT)
target_compile_options(context_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME context COMMAND context_test)

add_executable(token_flags_test token_flags_test.c)
target_link_libraries(token_flags_test PRIVATE libssig::ssig PkgConfig::P11_KIT)
target_compile_options(token_flags_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME token_flags COMMAND token_flags_test)

add_executable(sign_test sign_test.c)
target_link_libraries(sign_test PRIVATE libssig::ssig PkgConfig::P11_KIT OpenSSL::Crypto)
target_compile_options(sign_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME sign COMMAND sign_test)

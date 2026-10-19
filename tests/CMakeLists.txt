# This file is part of libssig.
# Copyright (C) 2026 Gustavo Calvo <tavo@tavo.cr>
# SPDX-License-Identifier: GPL-3.0-or-later
#
# See libssig/libssig.c for the full copyright and warranty notice.
# See LICENSE in the project root for the GNU General Public License.

add_executable(noop_test noop.test.c)
target_link_libraries(noop_test PRIVATE libssig::ssig)
target_compile_options(noop_test PRIVATE -Wall -Wextra -Wpedantic -Werror)

add_test(NAME noop COMMAND noop_test)

# Manual integration check using the locally configured PKCS#11 modules.
add_executable(list-tokens list-tokens.c)
target_link_libraries(list-tokens PRIVATE libssig::ssig PkgConfig::P11_KIT)
target_compile_options(list-tokens PRIVATE -Wall -Wextra -Wpedantic -Werror)

add_executable(session_test session.test.c)
target_link_libraries(session_test PRIVATE libssig::ssig PkgConfig::P11_KIT)
target_compile_options(session_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
add_test(NAME session COMMAND session_test)

/*
 * libssig - Simple digital signature library.
 * Copyright (C) 2026 Gustavo Calvo <tavo@tavo.cr>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 * See the LICENSE file in the project root for the full license text.
 */

#include <libssig/libssig.h>

void libssig_version(int* out_major, int* out_minor, int* out_patch) {
	if (out_major) {
		*out_major = LIBSSIG_VERSION_MAJOR;
	}

	if (out_minor) {
		*out_minor = LIBSSIG_VERSION_MINOR;
	}

	if (out_patch) {
		*out_patch = LIBSSIG_VERSION_PATCH;
	}
}

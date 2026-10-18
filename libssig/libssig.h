/*
 * This file is part of libssig.
 * Copyright (C) 2026 Gustavo Calvo <tavo@tavo.cr>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * See libssig/libssig.c for the full copyright and warranty notice.
 * See LICENSE in the project root for the GNU General Public License.
 */

#ifndef LIBSSIG_H
#define LIBSSIG_H

#include <stddef.h>

#define LIBSSIG_VERSION_MAJOR 0
#define LIBSSIG_VERSION_MINOR 1
#define LIBSSIG_VERSION_PATCH 0

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	unsigned char* uri;
} libssig_token;

void libssig_version(int* major, int* minor, int* patch);

int libssig_tokens(libssig_token** tokens);

#ifdef __cplusplus
}
#endif

#endif // LIBSSIG_H

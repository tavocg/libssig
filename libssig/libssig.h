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

typedef enum {
	LIBSSIG_OK = 0,
	LIBSSIG_ERROR_ARGUMENT,
	LIBSSIG_ERROR_MEMORY,
	LIBSSIG_ERROR_PKCS11,
	LIBSSIG_ERROR_MODULES,
	LIBSSIG_ERROR_URI,
} libssig_status;

typedef struct {
	char* uri;
	char* label;
	char* manufacturer;
	char* model;
	char* serial;
	unsigned long flags;
} libssig_token;

typedef struct {
	libssig_token* items;
	size_t count;
	unsigned long ck_rv;
} libssig_tokens;

void libssig_version(int* major, int* minor, int* patch);

libssig_status libssig_list_tokens(libssig_tokens* result);

void libssig_tokens_free(libssig_tokens* result);

#ifdef __cplusplus
}
#endif

#endif // LIBSSIG_H

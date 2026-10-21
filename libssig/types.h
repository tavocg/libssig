/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef LIBSSIG_TYPES_H
#define LIBSSIG_TYPES_H

#include <stdbool.h>
#include <stddef.h>

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
	LIBSSIG_ERROR_NOT_FOUND,
	LIBSSIG_ERROR_AMBIGUOUS,
	LIBSSIG_ERROR_UNSUPPORTED,
	LIBSSIG_ERROR_CRYPTO,
	LIBSSIG_ERROR_MAGIC,
	LIBSSIG_ERROR_FORMAT,
	LIBSSIG_ERROR_CONTENT_REQUIRED,
	LIBSSIG_ERROR_VERIFY,
	LIBSSIG_ERROR_TRUST,
	LIBSSIG_ERROR_TIMESTAMP,
	LIBSSIG_ERROR_OCSP,
	LIBSSIG_ERROR_REVOKED,
	LIBSSIG_ERROR_EVIDENCE,
} libssig_status;

/* Arreglo dinámico; cadenas propiedad de la biblioteca.
 * Su memoria se libera junto con el resultado que lo contiene. */
typedef struct {
	const char** items;
	size_t       count;
} libssig_string_list;

typedef enum {
	LIBSSIG_ALGO_RSA_PKCS,
	LIBSSIG_ALGO_RSA_PSS,
	LIBSSIG_ALGO_ECDSA,
} libssig_algo;

typedef enum {
	LIBSSIG_HASH_SHA256,
	LIBSSIG_HASH_SHA384,
	LIBSSIG_HASH_SHA512,
} libssig_hash;

typedef enum {
	LIBSSIG_FORMAT_CADES,
	LIBSSIG_FORMAT_CMS,
	LIBSSIG_FORMAT_PADES,
} libssig_format;

typedef enum {
	LIBSSIG_LEVEL_B_LTA = 0,
	LIBSSIG_LEVEL_B_B,
	LIBSSIG_LEVEL_B_T,
	LIBSSIG_LEVEL_B_LT,
} libssig_level;

/* Resultado en memoria propiedad del consumidor; liberar con
 * libssig_signature_free. No copiar una estructura con memoria pendiente. */
typedef struct {
	unsigned char* data;
	size_t         len;
	unsigned long  ck_rv;
} libssig_signature;

/* Shared result ownership for sign, extend and timestamp. */
void libssig_signature_free(libssig_signature* signature);

#ifdef __cplusplus
}
#endif

#endif

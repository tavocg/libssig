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

#include <stdbool.h>
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
	LIBSSIG_ERROR_NOT_FOUND,
	LIBSSIG_ERROR_AMBIGUOUS,
} libssig_status;

/* Inicializar con {0}. No copiar ni modificar impl.
 * Mantener abierto durante todas las operaciones y sesiones que lo usan.
 * El consumidor sincroniza el cierre y cualquier reemplazo del contexto. */
typedef struct {
	struct libssig_context_impl* impl;
} libssig_context;

libssig_status libssig_context_open(libssig_context* ctx);
void           libssig_context_close(libssig_context* ctx);

typedef struct {
	unsigned char major;
	unsigned char minor;
} libssig_token_version;

/* Memoria del resultado de certificados; liberar con libssig_certificates_free.
 */
typedef struct {
	/* ID binario; no es una cadena. NULL si el atributo no es accesible. */
	unsigned char* id;
	size_t         id_len;

	/* Etiqueta UTF-8 terminada en cero; NULL si no es accesible.
	 * label_len excluye el terminador. */
	char*  label;
	size_t label_len;

	/* Certificado X.509; NULL si no está disponible localmente. */
	unsigned char* der;
	size_t         der_len;
} libssig_certificate;

typedef struct {
	libssig_certificate* items;
	size_t               count;
	unsigned long        ck_rv;
} libssig_certificate_list;

/* Arreglo dinámico; cadenas constantes propiedad de la biblioteca.
 * Su memoria se libera junto con el resultado que lo contiene. */
typedef struct {
	const char** items;
	size_t       count;
} libssig_string_list;

/* Las cadenas pertenecen al resultado y se liberan con libssig_tokens_free. */
typedef struct {
	/* URI PKCS#11; puede coincidir con más de un token o módulo. */
	char* uri;

	/* Texto terminado en cero, sin los espacios de relleno finales. */
	char* label;
	char* manufacturer;
	char* model;
	char* serial;

	/* Máscara CKF_* de CK_TOKEN_INFO; no incluye flags del slot. */
	unsigned long flags;

	/* Nombres conocidos; bits desconocidos omitidos. Sin terminador NULL.
	 * Como máximo sizeof(unsigned long) * CHAR_BIT entradas.
	 * No modificar ni liberar por separado. */
	libssig_string_list flag_names;

	/* 0 indica sin límite fijo; ~0UL indica información no disponible. */
	unsigned long max_session_count;

	/* Incluye sesiones de lectura y lectura/escritura; ~0UL si no se sabe. */
	unsigned long session_count;

	/* 0 indica sin límite fijo; ~0UL indica información no disponible. */
	unsigned long max_rw_session_count;

	/* Sesiones de lectura/escritura; ~0UL si no se conoce la cantidad. */
	unsigned long rw_session_count;

	unsigned long         max_pin_len;
	unsigned long         min_pin_len;
	unsigned long         total_public_memory;
	unsigned long         free_public_memory;
	unsigned long         total_private_memory;
	unsigned long         free_private_memory;
	libssig_token_version hardware_version;
	libssig_token_version firmware_version;

	char utc_time[17];
} libssig_token;

typedef struct {
	libssig_token* items;
	size_t         count;
	unsigned long  ck_rv;
} libssig_token_list;

/* Escribe la versión de la biblioteca cargada; cada salida puede ser NULL. */
void libssig_version(int* out_major, int* out_minor, int* out_patch);

/* Requiere un contexto abierto. Liberar la salida antes de reutilizarla. */
libssig_status libssig_tokens(
    const libssig_context* ctx,
    libssig_token_list*    tokens,
    bool                   hardware_only
);

void libssig_tokens_free(libssig_token_list* tokens);

libssig_status libssig_certificates(
    const libssig_context*    ctx,
    const libssig_token*      token,
    libssig_certificate_list* certs
);

void libssig_certificates_free(libssig_certificate_list* certs);

#ifdef __cplusplus
}
#endif

#endif // LIBSSIG_H

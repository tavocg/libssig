/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef LIBSSIG_TOKENS_TOKENS_H
#define LIBSSIG_TOKENS_TOKENS_H

#include <libssig/context/context.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	unsigned char major;
	unsigned char minor;
} libssig_token_version;

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

typedef enum {
	LIBSSIG_TOKENS_ALL = 1u << 0,
} libssig_tokens_options;

/* Requiere un contexto abierto. Liberar la salida antes de reutilizarla.
 * Combinar opciones con |; 0 incluye solo tokens de hardware.
 * LIBSSIG_TOKENS_ALL incluye todos los tokens presentes.
 * Bits de opciones desconocidos devuelven LIBSSIG_ERROR_ARGUMENT. */
libssig_status libssig_tokens(
    const libssig_context* ctx,
    libssig_token_list*    tokens,
    unsigned int           options
);

void libssig_tokens_free(libssig_token_list* tokens);

#ifdef __cplusplus
}
#endif

#endif

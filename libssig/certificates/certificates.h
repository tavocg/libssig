/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef LIBSSIG_CERTIFICATES_CERTIFICATES_H
#define LIBSSIG_CERTIFICATES_CERTIFICATES_H

#include <libssig/tokens/tokens.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	LIBSSIG_KEY_USAGE_DIGITAL_SIGNATURE = 1u << 0,
	LIBSSIG_KEY_USAGE_CONTENT_COMMITMENT = 1u << 1,
	LIBSSIG_KEY_USAGE_KEY_ENCIPHERMENT = 1u << 2,
	LIBSSIG_KEY_USAGE_DATA_ENCIPHERMENT = 1u << 3,
	LIBSSIG_KEY_USAGE_KEY_AGREEMENT = 1u << 4,
	LIBSSIG_KEY_USAGE_KEY_CERT_SIGN = 1u << 5,
	LIBSSIG_KEY_USAGE_CRL_SIGN = 1u << 6,
	LIBSSIG_KEY_USAGE_ENCIPHER_ONLY = 1u << 7,
	LIBSSIG_KEY_USAGE_DECIPHER_ONLY = 1u << 8,
} libssig_key_usage;

typedef enum {
	LIBSSIG_CERTIFICATE_METADATA_UNAVAILABLE,
	LIBSSIG_CERTIFICATE_METADATA_VALID,
	LIBSSIG_CERTIFICATE_METADATA_INVALID,
} libssig_certificate_metadata_status;

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

	/* Extracción de metadatos; no valida confianza, vigencia ni revocación. */
	libssig_certificate_metadata_status metadata_status;
	bool                                key_usage_present;
	unsigned int                        key_usage;
	libssig_string_list                 key_usage_names;
	bool                                extended_key_usage_present;
	libssig_string_list
	     extended_key_usage; /* OIDs numéricos, incluidos desconocidos. */
	bool certificate_policies_present;
	libssig_string_list certificate_policies; /* Solo OIDs, sin qualifiers. */
} libssig_certificate;

typedef struct {
	libssig_certificate* items;
	size_t               count;
	unsigned long        ck_rv;
} libssig_certificate_list;

typedef enum {
	LIBSSIG_CERTIFICATES_ALL = 1u << 0,
} libssig_certificates_options;

/* 0: solo certificados con Key Usage contentCommitment y metadatos válidos.
 * ALL incluye usos distintos, desconocidos y DER ausente o inválido.
 * No requiere PIN ni comprueba CKA_SIGN; esa capacidad se valida al firmar.
 * Requiere contexto abierto; liberar la salida antes de reutilizarla.
 * Bits desconocidos devuelven LIBSSIG_ERROR_ARGUMENT. */
libssig_status libssig_certificates(
    const libssig_context*    ctx,
    const libssig_token*      token,
    libssig_certificate_list* certs,
    unsigned int              options
);

void libssig_certificates_free(libssig_certificate_list* certs);

#ifdef __cplusplus
}
#endif

#endif

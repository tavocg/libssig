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
	LIBSSIG_ERROR_UNSUPPORTED,
	LIBSSIG_ERROR_CRYPTO,
	LIBSSIG_ERROR_MAGIC,
	LIBSSIG_ERROR_FORMAT,
	LIBSSIG_ERROR_CONTENT_REQUIRED,
	LIBSSIG_ERROR_VERIFY,
	LIBSSIG_ERROR_TRUST,
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

/* Arreglo dinámico; cadenas propiedad de la biblioteca.
 * Su memoria se libera junto con el resultado que lo contiene. */
typedef struct {
	const char** items;
	size_t       count;
} libssig_string_list;

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
} libssig_format;

typedef enum {
	LIBSSIG_SIGN_DETACHED = 1u << 0,
} libssig_sign_options;

/* Todos los punteros son prestados y solo se usan durante la llamada.
 * Inicializar con {0}: RSA PKCS#1 v1.5, SHA-256 y CAdES B-B attached. */
typedef struct {
	const libssig_token*       token;
	const libssig_certificate* cert;
	/* Bytes originales, no un digest. */
	const unsigned char* data;
	size_t               data_len;
	/* No se conserva ni se solicita interactivamente. */
	const unsigned char* pin;
	size_t               pin_len;
	libssig_algo         algo;
	libssig_hash         hash;
	libssig_format       format;
	unsigned int         options;
	const char*
	    mime_type; /* CAdES: NULL detecta el tipo del contenido con libmagic. */
} libssig_sign_params;

/* Resultado en memoria propiedad del consumidor; liberar con
 * libssig_signature_free. No copiar una estructura con memoria pendiente. */
typedef struct {
	unsigned char* data;
	size_t         len;
	unsigned long  ck_rv;
} libssig_signature;

/* Requiere contexto abierto, token con URI y certificado con ID binario y DER.
 * Selecciona la clave privada por cert->id; debe ser única, del tipo adecuado y
 * permitir CKA_SIGN. No hay fallback de algoritmo/hash/mecanismo.
 * Datos hasta INT_MAX bytes; NULL, 0 permite firmar contenido vacío.
 * PIN NULL, 0 solicita la ruta protegida cuando es necesaria. Un PIN vacío
 * explícito usa un puntero no NULL con pin_len = 0.
 * options = 0 incorpora el contenido; SIGN_DETACHED genera firma separada.
 * Bits desconocidos devuelven ERROR_ARGUMENT.
 * Devuelve CMS/CAdES DER con el certificado incorporado, y comprueba
 * la firma con su clave pública. No valida confianza, vigencia ni revocación.
 * No lee/escribe documentos ni usa red; libmagic lee su base local si hace
 * falta detectar MIME. Un fallo de detección devuelve LIBSSIG_ERROR_MAGIC.
 * signingTime en CAdES es la hora local
 * declarada; no es un sello de tiempo de una TSA.
 * Liberar el resultado anterior antes de reutilizar la salida.
 * En error, la salida válida queda vacía; ck_rv conserva el código PKCS#11
 * cuando existe. Para errores locales puede ser cero: comprobar status. */
libssig_status libssig_sign(
    const libssig_context*     ctx,
    const libssig_sign_params* params,
    libssig_signature*         signature
);

/* Acepta NULL y resultados vacíos; deja data = NULL, len = ck_rv = 0. */
void libssig_signature_free(libssig_signature* signature);

typedef enum {
	LIBSSIG_VERIFY_SYSTEM_TRUST = 1u << 0,
} libssig_verify_options;

/* Punteros prestados durante la llamada; data contiene CMS/CAdES DER.
 * content = NULL, content_len = 0 indica contenido externo ausente.
 * Para contenido externo vacío, usar un puntero no NULL y len = 0.
 * Un contenedor attached rechaza content no NULL para evitar ambigüedad. */
typedef struct {
	const unsigned char* data;
	size_t               data_len;
	const unsigned char* content;
	size_t               content_len;
	unsigned int         options;
} libssig_verify_params;

/* Datos del firmante copiados; propiedad del resultado. */
typedef struct {
	unsigned char* cert_der;
	size_t         cert_der_len;
	char*          mime_type; /* NULL si no hay atributo MIME firmado. */
	long trust_error;         /* Código X.509 de OpenSSL; 0 si no hay error. */
} libssig_verify_signer;

typedef struct {
	libssig_verify_signer* signers;
	size_t                 count;
	bool                   detached;
	bool                   signature_valid;
	bool                   trust_checked;
	bool                   trusted;
} libssig_verify_result;

/* Sin contexto PKCS#11, token ni PIN. Verifica todos los firmantes.
 * 0 verifica firma, contenido y vínculos ESS presentes (incluido V2).
 * SYSTEM_TRUST exige además cadenas vigentes hasta el almacén predeterminado
 * de OpenSSL (incluye su configuración SSL_CERT_FILE/SSL_CERT_DIR).
 * No consulta red, OCSP ni CRL; no certifica cumplimiento completo CAdES.
 * ERROR_TRUST conserva firma válida, firmantes y errores de confianza.
 * Otros errores dejan salida vacía. Liberar antes de reutilizar. */
libssig_status libssig_verify(
    const libssig_verify_params* params,
    libssig_verify_result*       result
);
void libssig_verify_free(libssig_verify_result* result);

#ifdef __cplusplus
}
#endif

#endif // LIBSSIG_H

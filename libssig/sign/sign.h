/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef LIBSSIG_SIGN_SIGN_H
#define LIBSSIG_SIGN_SIGN_H

#include <libssig/certificates/certificates.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	LIBSSIG_SIGN_DETACHED = 1u << 0,
} libssig_sign_options;

struct libssig_verify_params;

struct libssig_sign_services;

/* Todos los punteros son prestados y solo se usan durante la llamada.
 * Inicializar con {0}: RSA PKCS#1 v1.5, SHA-256 y CAdES B-LTA attached.
 * B-T/LT/LTA requieren services; no se degrada el nivel al fallar. */
typedef struct {
	const libssig_token*       token;
	const libssig_certificate* cert;
	/* Bytes originales, no un digest. */
	const unsigned char* data;
	size_t               data_len;
	/* No se conserva ni se solicita interactivamente. */
	const unsigned char*                pin;
	size_t                              pin_len;
	libssig_algo                        algo;
	libssig_hash                        hash;
	libssig_format                      format;
	libssig_level                       level;
	const struct libssig_sign_services* services;
	unsigned int                        options;
	const char*
	    mime_type; /* CAdES: NULL detecta el tipo del contenido con libmagic. */
} libssig_sign_params;

/* Requiere contexto abierto, token con URI y certificado con ID binario y DER.
 * Selecciona la clave privada por cert->id; debe ser única, del tipo adecuado y
 * permitir CKA_SIGN. No hay fallback de algoritmo/hash/mecanismo.
 * Datos hasta INT_MAX bytes; NULL, 0 permite firmar contenido vacío.
 * PIN NULL, 0 solicita la ruta protegida cuando es necesaria. Un PIN vacío
 * explícito usa un puntero no NULL con pin_len = 0.
 * options = 0 incorpora el contenido; SIGN_DETACHED genera firma separada.
 * Bits desconocidos devuelven ERROR_ARGUMENT.
 * Devuelve CMS/CAdES DER, PDF, XML XAdES o JSON JAdES según format. Comprueba
 * la firma con la clave pública. B-B no valida confianza, vigencia ni
 * revocación; B-T valida la TSA y LT/LTA recogen evidencias con services. PAdES
 * exige PDF y rechaza SIGN_DETACHED. No lee/escribe documentos ni abre
 * conexiones: services aporta el transporte. libmagic lee su base local si hace
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

/* Application-owned transport; no HTTP implementation inside libssig.
 * request=NULL means GET (issuer certificate or CRL); otherwise POST.
 * response owns malloc-compatible memory, released with signature_free.
 * Return an error for unsuccessful HTTP responses; no redirects required. */
typedef enum {
	LIBSSIG_FETCH_TIMESTAMP,
	LIBSSIG_FETCH_OCSP,
	LIBSSIG_FETCH_CERTIFICATE,
	LIBSSIG_FETCH_CRL,
} libssig_fetch_kind;

typedef libssig_status (*libssig_exchange)(
    void*                user_data,
    libssig_fetch_kind   kind,
    const char*          url,
    const unsigned char* request,
    size_t               request_len,
    libssig_signature*   response
);

typedef struct libssig_sign_services {
	libssig_exchange exchange;
	void*            user_data;
	const char*      tsa_url;
	/* Only trust fields are used. NULL uses system trust for document and TSA.
	 */
	const struct libssig_verify_params* trust;
	unsigned long                       max_age;
	unsigned long                       clock_skew;
	/* OCSP responders that omit the nonce require explicit opt-in. */
	unsigned int ocsp_options;
} libssig_sign_services;

#ifdef __cplusplus
}
#endif

#endif

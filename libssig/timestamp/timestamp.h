/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef LIBSSIG_TIMESTAMP_TIMESTAMP_H
#define LIBSSIG_TIMESTAMP_TIMESTAMP_H

#include <libssig/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	LIBSSIG_TIMESTAMP_SYSTEM_TRUST = 1u << 0,
} libssig_timestamp_options;

/* Contenedor CAdES DER, JAdES JSON o XAdES XML; signer_index identifica al
 * firmante en esta entrada. hash = 0 usa SHA-256 para el sello,
 * independientemente de la firma original. policy_oid opcional: OID numérico de
 * la política exigida a la TSA. */
typedef struct {
	const unsigned char* data;

	size_t       data_len;
	size_t       signer_index;
	libssig_hash hash;
	const char*  policy_oid;
} libssig_timestamp_request_params;

/* Genera TimeStampReq DER con nonce aleatorio de 128 bits y certReq=true.
 * Sella el valor de firma; no necesita el documento de una firma detached.
 * Comprueba atributos firmados y vínculo ESS del firmante seleccionado,
 * pero no el documento original, su confianza ni cumplimiento completo CAdES.
 * Rechaza un sello existente en el firmante seleccionado.
 * Resultado propietario: liberar con libssig_signature_free; ck_rv = 0. */
libssig_status libssig_timestamp_request(
    const libssig_timestamp_request_params* params,
    libssig_signature*                      request
);

typedef struct {
	const unsigned char* data;

	size_t               data_len;
	size_t               signer_index;
	const unsigned char* request;

	size_t               request_len;
	const unsigned char* response;

	size_t response_len;
	/* Confianza independiente para la TSA: PEM/DER, igual que verify. */
	const unsigned char* ca_data;

	size_t ca_data_len;
	/* CA autofirmadas de respaldo PEM/DER: hasta 16 MiB y 1024 certificados.
	 * Consultadas tras los almacenes principales.
	 * No sustituyen errores de firma, vigencia, propósito o revocación.
	 * Requieren ca_data o la opción SYSTEM_TRUST del grupo. */
	const unsigned char* fallback_ca_data;
	size_t               fallback_ca_data_len;
	const unsigned char* intermediates_data;

	size_t       intermediates_data_len;
	unsigned int options;
} libssig_timestamp_params;

/* Valida respuesta RFC 3161 contra solicitud y firma, nonce, política,
 * firma TSA, ESS, EKU timeStamping y confianza. Exige ca_data o SYSTEM_TRUST.
 * Incorpora el token en signature-time-stamp, sigTst o SignatureTimeStamp.
 * Rechaza genTime a más de 300 segundos en el futuro. Valida la cadena TSA
 * a la hora actual; no consulta revocación ni establece validación histórica.
 * ERROR_TIMESTAMP indica respuesta no concedida; ERROR_TRUST, cadena TSA
 * no confiable; ERROR_VERIFY, respuesta/firma/solicitud incompatibles.
 * No usa red, archivos, token ni PIN; la aplicación transporta TSQ/TSR.
 * Resultado propietario: liberar con libssig_signature_free; vacío en error.
 * Entradas DER hasta INT_MAX bytes; no modifica la entrada. */
libssig_status libssig_timestamp(
    const libssig_timestamp_params* params,
    libssig_signature*              signature
);

#ifdef __cplusplus
}
#endif

#endif

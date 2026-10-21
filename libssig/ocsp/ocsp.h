/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef LIBSSIG_OCSP_OCSP_H
#define LIBSSIG_OCSP_OCSP_H

#include <libssig/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	LIBSSIG_OCSP_FAILED,
	LIBSSIG_OCSP_GOOD,
	LIBSSIG_OCSP_REVOKED,
	LIBSSIG_OCSP_UNKNOWN,
} libssig_ocsp_status;

typedef enum {
	LIBSSIG_OCSP_SYSTEM_TRUST = 1u << 0,
	LIBSSIG_OCSP_ALLOW_MISSING_NONCE = 1u << 1,
} libssig_ocsp_options;

/* Certificado y emisor: un X.509 PEM o DER por buffer; punteros prestados. */
typedef struct {
	const unsigned char* cert_data;
	size_t               cert_data_len;
	const unsigned char* issuer_data;
	size_t               issuer_data_len;
} libssig_ocsp_request_params;

/* Solicitud DER y URLs HTTP(S) del AIA del certificado; memoria propia. */
typedef struct {
	unsigned char*      data;
	size_t              len;
	libssig_string_list urls;
} libssig_ocsp_query;

/* Una consulta, CertID SHA-1 por compatibilidad OCSP y nonce aleatorio de
 * 32 bytes. SHA-1 solo identifica emisor/serial; no firma la solicitud.
 * Sin HTTP ni confianza implícita en el emisor. Rechaza emisores incorrectos.
 * Liberar la salida antes de reutilizarla; vacía en error. */
libssig_status libssig_ocsp_request(
    const libssig_ocsp_request_params* params,
    libssig_ocsp_query*                query
);
void libssig_ocsp_request_free(libssig_ocsp_query* query);

typedef struct {
	const unsigned char* cert_data;
	size_t               cert_data_len;
	const unsigned char* issuer_data;
	size_t               issuer_data_len;
	const unsigned char* request;
	size_t               request_len;
	const unsigned char* response;
	size_t               response_len;
	const unsigned char* ca_data;
	size_t               ca_data_len;
	/* CA autofirmadas de respaldo PEM/DER: hasta 16 MiB y 1024 certificados.
	 * Consultadas tras los almacenes principales.
	 * No sustituyen errores de firma, vigencia, propósito o revocación.
	 * Requieren ca_data o la opción SYSTEM_TRUST del grupo. */
	const unsigned char* fallback_ca_data;
	size_t               fallback_ca_data_len;
	const unsigned char* intermediates_data;
	size_t               intermediates_data_len;
	unsigned int         options;
	/* Segundos; 0 usa 86400 de antigüedad máxima y 300 de tolerancia. */
	unsigned long max_age;
	unsigned long clock_skew;
} libssig_ocsp_verify_params;

/* Sin memoria dinámica. valid indica respuesta autenticada, vigente y
 * correspondiente al certificado, incluso si status es REVOKED o UNKNOWN.
 * error es el retorno de ocsp_verify; response_status es el código RFC 6960
 * (-1 si no se decodificó), reason es el código CRL (-1 si no aplica).
 * Fechas UTC ISO 8601, precisión de segundos; vacías si no son aplicables. */
typedef struct {
	libssig_ocsp_status status;
	libssig_status      error;
	bool                valid;
	int                 response_status;
	int                 reason;
	char                produced_at[21];
	char                this_update[21];
	char                next_update[21];
	char                revocation_time[21];
} libssig_ocsp_result;

/* Exige ca_data o SYSTEM_TRUST. Valida emisor, CertID, respondedor autorizado,
 * firma, cadena, nonce y fechas a la hora actual. No consulta red ni CRL.
 * OK significa respuesta válida: comprobar status para GOOD/REVOKED/UNKNOWN.
 * Sin respuesta válida queda FAILED. ALLOW_MISSING_NONCE permite únicamente
 * nonce ausente en la respuesta; nunca acepta nonce distinto.
 * Entradas hasta INT_MAX bytes. No valida vigencia del certificado consultado
 * ni revocación recursiva del respondedor. */
libssig_status libssig_ocsp_verify(
    const libssig_ocsp_verify_params* params,
    libssig_ocsp_result*              result
);

#ifdef __cplusplus
}
#endif

#endif

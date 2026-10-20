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
	LIBSSIG_ERROR_TIMESTAMP,
	LIBSSIG_ERROR_OCSP,
	LIBSSIG_ERROR_REVOKED,
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
	LIBSSIG_FORMAT_PADES,
} libssig_format;

typedef enum {
	LIBSSIG_SIGN_DETACHED = 1u << 0,
} libssig_sign_options;

typedef enum {
	LIBSSIG_LEVEL_B_LTA = 0,
	LIBSSIG_LEVEL_B_B,
	LIBSSIG_LEVEL_B_T,
	LIBSSIG_LEVEL_B_LT,
} libssig_level;

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
 * Devuelve CMS/CAdES DER o un PDF firmado según format. Comprueba la firma
 * con la clave pública. B-B no valida confianza, vigencia ni revocación;
 * B-T valida la TSA y LT/LTA recogen evidencias con services.
 * PAdES exige PDF y rechaza SIGN_DETACHED.
 * No lee/escribe documentos ni abre conexiones: services aporta el transporte.
 * libmagic lee su base local si hace
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

/* Evidencia para un firmante de verify; tsa=true consulta su certificado TSA.
 * Confianza tomada del grupo correspondiente de verify_params. Solo admite
 * ALLOW_MISSING_NONCE en options; SYSTEM_TRUST se decide en verify_params.
 * response=NULL, len=0 representa una consulta sin respuesta utilizable. */
typedef struct {
	size_t               signer_index;
	bool                 tsa;
	const unsigned char* issuer_data;
	size_t               issuer_data_len;
	const unsigned char* request;
	size_t               request_len;
	const unsigned char* response;
	size_t               response_len;
	unsigned int         options;
	unsigned long        max_age;
	unsigned long        clock_skew;
} libssig_ocsp_evidence;

typedef enum {
	LIBSSIG_VERIFY_SYSTEM_TRUST = 1u << 0,
	LIBSSIG_VERIFY_TSA_SYSTEM_TRUST = 1u << 1,
	LIBSSIG_VERIFY_REQUIRE_TIMESTAMP = 1u << 2,
	LIBSSIG_VERIFY_REQUIRE_OCSP = 1u << 3,
	LIBSSIG_VERIFY_REQUIRE_TSA_OCSP = 1u << 4,
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
	/* PEM de uno o varios certificados, o un certificado DER.
	 * ca_data activa validación de confianza con estas raíces.
	 * SYSTEM_TRUST agrega las raíces del sistema a las proporcionadas.
	 * Los intermediarios nunca se incorporan al almacén confiable. */
	const unsigned char* ca_data;

	size_t               ca_data_len;
	const unsigned char* intermediates_data;

	size_t intermediates_data_len;
	/* Confianza TSA independiente; no hereda las raíces del firmante. */
	const unsigned char* tsa_ca_data;

	size_t               tsa_ca_data_len;
	const unsigned char* tsa_intermediates_data;

	size_t                       tsa_intermediates_data_len;
	const libssig_ocsp_evidence* ocsp;

	size_t       ocsp_count;
	unsigned int options;
} libssig_verify_params;

/* Resultado del sello del firmante; valid comprueba firma, ESS, propósito TSA
 * y vínculo con la firma del documento. La confianza se evalúa por separado.
 * time contiene UTC ISO 8601 a precisión de segundos, solo si valid = true.
 * Ausente: present = false, status = ERROR_NOT_FOUND. cert_der pertenece al
 * resultado y se libera con libssig_verify_free. */
typedef struct {
	bool           present;
	bool           valid;
	bool           trust_checked;
	bool           trusted;
	libssig_status status;
	long           trust_error;
	char           time[21];
	unsigned char* cert_der;

	size_t              cert_der_len;
	libssig_ocsp_result ocsp;
} libssig_verify_timestamp;

/* Datos del firmante copiados; propiedad del resultado. */
typedef struct {
	unsigned char* cert_der;
	size_t         cert_der_len;
	char*          mime_type; /* NULL si no hay atributo MIME firmado. */
	long trust_error;         /* Código X.509 de OpenSSL; 0 si no hay error. */
	libssig_verify_timestamp timestamp;
	libssig_verify_timestamp archive;
	libssig_ocsp_result      ocsp;
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
 * Sin ca_data ni SYSTEM_TRUST verifica firma, contenido y vínculos ESS.
 * ca_data exige una cadena vigente hasta las raíces proporcionadas.
 * SYSTEM_TRUST suma las raíces del almacén predeterminado de OpenSSL
 * (incluye SSL_CERT_FILE/SSL_CERT_DIR) a ca_data, si está presente.
 * Intermediarios requieren ca_data o SYSTEM_TRUST.
 * Bundles hasta INT_MAX bytes; vacíos, inválidos o con basura se rechazan.
 * No usa red ni descarga OCSP/CRL; puede validar evidencia OCSP proporcionada.
 * No certifica cumplimiento completo CAdES.
 * Verifica sellos presentes sin requerir la solicitud original.
 * TSA_SYSTEM_TRUST suma raíces del sistema solo para TSA. REQUIRE_TIMESTAMP
 * exige un sello válido en cada firmante. tsa_ca_data activa confianza TSA.
 * El sello se verifica a la hora actual, sin validación histórica.
 * time es una fecha autenticada solo si la TSA es confiable.
 * ERROR_TIMESTAMP conserva la firma válida e informa sellos inválidos/ausentes.
 * ERROR_TRUST conserva firma válida, firmantes y errores de confianza.
 * REQUIRE_OCSP exige GOOD para cada firmante; REQUIRE_TSA_OCSP exige un
 * sello válido y OCSP GOOD para su TSA. Requieren confianza del grupo indicado.
 * Evidencia opcional presente también se valida; no se ignoran sus errores.
 * ERROR_REVOKED conserva firma y estado revocado autenticado; ERROR_OCSP
 * conserva estados desconocidos, fallidos o ausentes cuando se exigen.
 * trusted solo describe cadena de certificados, no estado de revocación.
 * Otros errores dejan salida vacía. Liberar antes de reutilizar. */
libssig_status libssig_verify(
    const libssig_verify_params* params,
    libssig_verify_result*       result
);
void libssig_verify_free(libssig_verify_result* result);

typedef enum {
	LIBSSIG_TIMESTAMP_SYSTEM_TRUST = 1u << 0,
} libssig_timestamp_options;

/* Contenedor CAdES DER; signer_index identifica al firmante en esta entrada.
 * hash = 0 usa SHA-256 para el sello, independientemente de la firma original.
 * policy_oid opcional: OID numérico de la política exigida a la TSA. */
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

	size_t               ca_data_len;
	const unsigned char* intermediates_data;

	size_t       intermediates_data_len;
	unsigned int options;
} libssig_timestamp_params;

/* Valida respuesta RFC 3161 contra solicitud y firma, nonce, política,
 * firma TSA, ESS, EKU timeStamping y confianza. Exige ca_data o SYSTEM_TRUST.
 * Incorpora el token como atributo no firmado signature-time-stamp.
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
	const libssig_verify_params* trust;
	unsigned long                max_age;
	unsigned long                clock_skew;
	/* OCSP responders that omit the nonce require explicit opt-in. */
	unsigned int ocsp_options;
} libssig_sign_services;

/* Extend CAdES or a single-signature PDF without accessing a token. content is
 * required for detached signatures. B-LTA is the zero/default level; missing
 * services fail explicitly. Output is empty on failure. Existing signatures are
 * never downgraded. */
typedef struct {
	const unsigned char*         data;
	size_t                       data_len;
	const unsigned char*         content;
	size_t                       content_len;
	libssig_level                level;
	libssig_hash                 hash;
	const libssig_sign_services* services;
} libssig_extend_params;

libssig_status libssig_extend(
    const libssig_extend_params* params,
    libssig_signature*           signature
);

#ifdef __cplusplus
}
#endif

#endif // LIBSSIG_H

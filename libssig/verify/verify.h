/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef LIBSSIG_VERIFY_VERIFY_H
#define LIBSSIG_VERIFY_VERIFY_H

#include <libssig/ocsp/ocsp.h>

#ifdef __cplusplus
extern "C" {
#endif

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
	LIBSSIG_VERIFY_HISTORICAL = 1u << 5,
	LIBSSIG_VERIFY_CURRENT_TIME = 1u << 6,
} libssig_verify_options;

/* Respuesta OCSP completa o CRL, DER. Prestada durante verify; no es una raíz.
 */
typedef struct {
	const unsigned char* data;
	size_t               len;
} libssig_revocation_evidence;

/* Punteros prestados durante la llamada; data contiene CMS/CAdES DER.
 * content = NULL, content_len = 0 indica contenido externo ausente.
 * Para contenido externo vacío, usar un puntero no NULL y len = 0.
 * Un contenedor attached rechaza content no NULL para evitar ambigüedad. */
typedef struct libssig_verify_params {
	const unsigned char* data;
	size_t               data_len;
	const unsigned char* content;
	size_t               content_len;
	/* PEM de uno o varios certificados, o un certificado DER.
	 * ca_data activa validación de confianza con estas raíces.
	 * SYSTEM_TRUST agrega las raíces del sistema a las proporcionadas.
	 * Los intermediarios nunca se incorporan al almacén confiable. */
	const unsigned char* ca_data;

	size_t ca_data_len;
	/* CA autofirmadas de respaldo PEM/DER: hasta 16 MiB y 1024 certificados.
	 * Consultadas tras los almacenes principales.
	 * No sustituyen errores de firma, vigencia, propósito o revocación.
	 * Requieren ca_data o la opción SYSTEM_TRUST del grupo. */
	const unsigned char* fallback_ca_data;
	size_t               fallback_ca_data_len;
	const unsigned char* intermediates_data;

	size_t intermediates_data_len;
	/* Confianza TSA independiente; no hereda las raíces del firmante. */
	const unsigned char* tsa_fallback_ca_data;
	size_t               tsa_fallback_ca_data_len;
	const unsigned char* tsa_ca_data;

	size_t               tsa_ca_data_len;
	const unsigned char* tsa_intermediates_data;

	size_t                       tsa_intermediates_data_len;
	const libssig_ocsp_evidence* ocsp;

	size_t ocsp_count;
	/* Evidencia actual para la cadena del último sello de
	 * archivo. No sustituye las evidencias históricas protegidas por él. */
	const libssig_revocation_evidence* current_revocations;
	size_t                             current_revocation_count;
	unsigned int                       options;
} libssig_verify_params;

/* Ancla de una cadena validada: huella SHA-256 DER, no un nombre inferido.
 * FALLBACK indica una raíz consultada después de los almacenes principales. */
typedef enum {
	LIBSSIG_TRUST_NONE = 0,
	LIBSSIG_TRUST_SYSTEM,
	LIBSSIG_TRUST_ADDITIONAL,
	LIBSSIG_TRUST_FALLBACK
} libssig_trust_source;
typedef struct {
	libssig_trust_source source;
	unsigned char        sha256[32];
} libssig_trust_anchor;

/* Resultado del sello del firmante; valid comprueba firma, ESS, propósito TSA
 * y vínculo con la firma del documento. La confianza se evalúa por separado.
 * time contiene UTC ISO 8601 a precisión de segundos, solo si valid = true.
 * Ausente: present = false, status = ERROR_NOT_FOUND. cert_der pertenece al
 * resultado y se libera con libssig_verify_free. */
typedef struct {
	bool                 present;
	bool                 valid;
	bool                 trust_checked;
	bool                 trusted;
	libssig_status       status;
	long                 trust_error;
	libssig_trust_anchor anchor;
	char                 time[21];
	unsigned char*       cert_der;

	size_t              cert_der_len;
	libssig_ocsp_result ocsp;
} libssig_verify_timestamp;

typedef enum {
	LIBSSIG_HISTORY_NOT_CHECKED = 0,
	LIBSSIG_HISTORY_VALID,
	LIBSSIG_HISTORY_INCOMPLETE,
	LIBSSIG_HISTORY_REVOKED,
	LIBSSIG_HISTORY_UNTRUSTED,
} libssig_history_status;

/* Datos del firmante copiados; propiedad del resultado. */
typedef struct {
	unsigned char* cert_der;
	size_t         cert_der_len;
	char*          mime_type; /* NULL si no hay atributo MIME firmado. */
	long trust_error;         /* Código X.509 de OpenSSL; 0 si no hay error. */
	libssig_trust_anchor     anchor;
	libssig_verify_timestamp timestamp;
	libssig_verify_timestamp archive;
	libssig_ocsp_result      ocsp;
	libssig_history_status   history;
	/* Nivel detectado por evidencias; solo es válido si level_detected.
	 * level_validated requiere completar la política correspondiente y
	 * confianza. */
	libssig_level level;
	bool          level_detected;
	bool          level_validated;
	/* Instante acreditado por el sello de firma, UTC ISO 8601. */
	char validation_time[21];
	bool revocation_checked;
} libssig_verify_signer;

typedef struct {
	libssig_verify_signer* signers;
	size_t                 count;
	bool                   detached;
	bool                   signature_valid;
	libssig_format         format;
	bool                   trust_checked;
	bool                   trusted;
} libssig_verify_result;

/* Sin contexto PKCS#11, token ni PIN. Verifica todos los firmantes.
 * Sin ca_data ni SYSTEM_TRUST B-B/B-T permiten comprobar firma/contenido/ESS;
 * LT/LTA requieren confianza para completar sus políticas automáticas.
 * ca_data exige una cadena vigente hasta las raíces proporcionadas.
 * SYSTEM_TRUST suma los almacenes predeterminados de OpenSSL (incluye
 * SSL_CERT_FILE/SSL_CERT_DIR) y los nativos de Windows/macOS a ca_data.
 * Las anclas nativas requieren además validación offline del sistema sobre
 * la misma cadena, fecha y propósito; no sustituyen errores de OpenSSL.
 * Las raíces explícitas y las de OpenSSL mantienen su confianza independiente.
 * Intermediarios requieren ca_data o SYSTEM_TRUST.
 * Bundles hasta INT_MAX bytes; vacíos, inválidos o con basura se rechazan.
 * No usa red ni descarga OCSP/CRL; puede validar evidencia OCSP proporcionada.
 * No certifica cumplimiento completo CAdES.
 * Verifica sellos presentes sin requerir la solicitud original.
 * TSA_SYSTEM_TRUST suma raíces del sistema solo para TSA. REQUIRE_TIMESTAMP
 * exige un sello válido en cada firmante. tsa_ca_data activa confianza TSA.
 * HISTORICAL exige confianza documental y TSA, sello de firma y de archivo,
 * y evidencia protegida para todas las cadenas (excepto raíces confiables).
 * La cadena documental y del sello de firma se evalúan en su fecha acreditada;
 * el último sello de archivo requiere una cadena y revocación vigentes hoy.
 * ERROR_EVIDENCE conserva resultados e indica evidencia ausente/no utilizable.
 * Por defecto detecta evidencias y selecciona la política: B-B/B-T vigente,
 * B-LT con revocación incluida vigente y B-LTA histórica. No omite fallos para
 * informar un nivel inferior. level_detected no certifica conformidad ETSI.
 * CURRENT_TIME desactiva esta selección y conserva comprobaciones actuales
 * de firma/confianza/sellos y OCSP explícito; no acredita niveles LT/LTA.
 * HISTORICAL exige B-LTA incluso si no se detecta; incompatible con
 * CURRENT_TIME. time es una fecha autenticada solo si la TSA es confiable.
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

#ifdef __cplusplus
}
#endif

#endif

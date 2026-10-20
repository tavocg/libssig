/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef LIBSSIG_INTERNAL_H
#define LIBSSIG_INTERNAL_H

#include <libssig/libssig.h>
#include <p11-kit/p11-kit.h>

struct libssig_context_impl {
	CK_FUNCTION_LIST** modules;
};

/* El contexto debe permanecer abierto mientras existan sesiones. */
typedef struct {
	CK_FUNCTION_LIST* module;
	CK_SLOT_ID        slot;
	CK_SESSION_HANDLE handle;
	bool              open;
} libssig_session;

/* Inicializar los recursos con {0}; cerrarlos antes de reutilizarlos. */
libssig_status libssig_session_open(
    const libssig_context* ctx,
    const char*            uri,
    libssig_session*       s,
    CK_RV*                 out_rv
);
/* No guarda el PIN. NULL, 0 solicita la ruta protegida del dispositivo.
 * Un PIN vacío explícito se pasa con un puntero no NULL y longitud cero. */
libssig_status libssig_session_login(
    libssig_session*     s,
    const unsigned char* pin,
    size_t               pin_len,
    CK_RV*               out_rv
);
CK_RV libssig_session_close(libssig_session* s);

libssig_status libssig_certificates_collect(
    libssig_session*          s,
    libssig_certificate_list* certs,
    unsigned int              options,
    CK_RV*                    out_rv
);

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

/* Firma interna: datos originales, no un digest. ID binario obligatorio.
 * No conserva PIN ni handles. El contexto permanece abierto.
 * NULL, 0 como PIN solicita autenticación protegida cuando sea necesaria. */
typedef struct {
	const libssig_token* token;
	const unsigned char* id;
	size_t               id_len;
	const unsigned char* pin;
	size_t               pin_len;
	const unsigned char* data;
	size_t               data_len;
	libssig_algo         algo;
	libssig_hash         hash;
	const char* mime_type; /* CAdES: NULL usa application/octet-stream. */
} libssig_sign_params;

typedef struct {
	unsigned char* data;
	size_t         len;
	unsigned long  ck_rv;
} libssig_signature;

/* Handle válido únicamente mientras s permanezca abierta. */
libssig_status libssig_private_key_find(
    libssig_session*     s,
    const unsigned char* id,
    size_t               id_len,
    CK_KEY_TYPE          expected_type,
    CK_OBJECT_HANDLE*    out_key,
    CK_RV*               out_rv
);

/* Salida inicializada con {0}; liberar antes de reutilizar.
 * Requiere el mecanismo combinado del algoritmo y hash, sin fallback.
 * RSA: bytes de firma. ECDSA: r || s de PKCS#11, no DER.
 * PSS usa MGF1 con el mismo hash y salt del tamaño del digest.
 * No produce CMS/CAdES. */
libssig_status libssig_session_sign(
    const libssig_context*     ctx,
    const libssig_sign_params* params,
    libssig_signature*         signature
);
void libssig_signature_free(libssig_signature* signature);

/* Metadatos propiedad del certificado; leer sobre una salida vacía. */
libssig_status libssig_certificate_metadata_read(libssig_certificate* cert);
void           libssig_certificate_metadata_clear(libssig_certificate* cert);

/* CMS SignedData DER detached, con certificado, sin atributos firmados.
 * No es CAdES. Firma los bytes originales (máximo INT_MAX) y comprueba
 * correspondencia criptográfica, no confianza/vigencia/revocación.
 * El ID del certificado debe coincidir con params->id.
 * Liberar salida con libssig_signature_free antes de reutilizar. */
libssig_status libssig_cms_sign(
    const libssig_context*     ctx,
    const libssig_sign_params* params,
    const libssig_certificate* cert,
    libssig_signature*         output
);

/* CAdES B-B DER detached: atributos firmados y signingCertificateV2.
 * Mismas reglas de propiedad y límites que libssig_cms_sign.
 * signingTime es hora declarada local, no un sello de tiempo de una TSA. */
libssig_status libssig_cades_sign(
    const libssig_context*     ctx,
    const libssig_sign_params* params,
    const libssig_certificate* cert,
    libssig_signature*         output
);

#endif

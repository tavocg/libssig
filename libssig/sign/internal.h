/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef LIBSSIG_SIGN_INTERNAL_H
#define LIBSSIG_SIGN_INTERNAL_H

#include "mime.h"
#include <libssig/session.h>
#include <libssig/sign/sign.h>
#include <openssl/cms.h>

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
	unsigned int         options;
	bool                 pades;
	const char*          mime_type; /* CAdES: NULL detecta MIME con libmagic. */
} libssig_key_sign_params;

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
    const libssig_context*         ctx,
    const libssig_key_sign_params* params,
    libssig_signature*             signature
);

/* CMS SignedData DER, con certificado, sin atributos firmados.
 * No es CAdES. Firma los bytes originales (máximo INT_MAX) y comprueba
 * correspondencia criptográfica, no confianza/vigencia/revocación.
 * El ID del certificado debe coincidir con params->id.
 * Liberar salida con libssig_signature_free antes de reutilizar. */
libssig_status libssig_cms_sign(
    const libssig_context*         ctx,
    const libssig_key_sign_params* params,
    const libssig_certificate*     cert,
    libssig_signature*             output
);

/* CAdES B-B DER: atributos firmados y signingCertificateV2.
 * Mismas reglas de propiedad y límites que libssig_cms_sign.
 * signingTime es hora declarada local, no un sello de tiempo de una TSA. */
libssig_status libssig_cades_v131_sign(
    const libssig_context*         ctx,
    const libssig_key_sign_params* params,
    const libssig_certificate*     cert,
    libssig_signature*             output
);

#define LIBSSIG_CADES_MIME_TYPE_OID "0.4.0.1733.2.1"

bool libssig_cades_v131_attributes_add(
    CMS_SignerInfo*                signer,
    X509*                          cert,
    const libssig_key_sign_params* params,
    const EVP_MD*                  digest
);
/* DER SET OF firmado por el token; liberar con OPENSSL_free. */
unsigned char* libssig_cades_v131_attributes_encode(
    CMS_SignerInfo* signer,
    size_t*         out_len
);

libssig_status libssig_pades_v121_sign(
    const libssig_context*     ctx,
    const libssig_sign_params* params,
    libssig_signature*         output
);

#endif

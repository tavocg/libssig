/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef LIBSSIG_CMS_INTERNAL_H
#define LIBSSIG_CMS_INTERNAL_H

#include <libssig/internal.h>
#include <openssl/cms.h>

#define LIBSSIG_CADES_MIME_TYPE_OID "0.4.0.1733.2.1"

bool libssig_cades_attributes_add(
    CMS_SignerInfo*            signer,
    X509*                      cert,
    const libssig_sign_params* params,
    const EVP_MD*              digest
);
/* DER SET OF firmado por el token; liberar con OPENSSL_free. */
unsigned char* libssig_cades_attributes_encode(
    CMS_SignerInfo* signer,
    size_t*         out_len
);

#endif

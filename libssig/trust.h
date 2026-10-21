/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef LIBSSIG_TRUST_H
#define LIBSSIG_TRUST_H

#include <libssig/libssig.h>
#include <openssl/cms.h>

libssig_status libssig_verify_certs_parse(
    const unsigned char* data,
    size_t               len,
    STACK_OF(X509) * *out_certs
);
libssig_status libssig_verify_certs_append(
    STACK_OF(X509) * certs,
    const STACK_OF(X509) * extra
);
libssig_status libssig_verify_store_create(
    const libssig_verify_params* params,
    const STACK_OF(X509) * roots,
    X509_STORE** out_store
);
bool libssig_verify_ess_check(
    CMS_SignerInfo* s,
    X509*           cert,
    STACK_OF(X509) * certs
);
bool libssig_ocsp_buffer_valid(
    const unsigned char* data,
    size_t               len,
    bool                 required
);

#endif

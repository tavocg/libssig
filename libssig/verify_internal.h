/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef LIBSSIG_VERIFY_INTERNAL_H
#define LIBSSIG_VERIFY_INTERNAL_H

#include <libssig/libssig.h>
#include <openssl/cms.h>

/* Owned stacks; release using sk_X509_pop_free(..., X509_free). */
libssig_status libssig_verify_certs_parse(
    const unsigned char* data,
    size_t               len,
    STACK_OF(X509) * *out_certs
);
libssig_status libssig_verify_certs_append(
    STACK_OF(X509) * certs,
    const STACK_OF(X509) * extra
);
libssig_status libssig_verify_trust_check(
    CMS_ContentInfo*             cms,
    const libssig_verify_params* params,
    const STACK_OF(X509) * roots,
    STACK_OF(X509) * certs,
    libssig_verify_result* result
);

bool libssig_verify_ess_check(
    CMS_SignerInfo* s,
    X509*           cert,
    STACK_OF(X509) * certs
);
libssig_status libssig_verify_store_create(
    const libssig_verify_params* params,
    const STACK_OF(X509) * roots,
    X509_STORE** out_store
);

#endif

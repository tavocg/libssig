/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef LIBSSIG_OCSP_INTERNAL_H
#define LIBSSIG_OCSP_INTERNAL_H
#include <libssig/verify_internal.h>
#include <openssl/ocsp.h>

libssig_status libssig_ocsp_certificate(
    const unsigned char* data,
    size_t               len,
    X509**               out_cert
);
bool libssig_ocsp_issuer_valid(X509* cert, X509* issuer);
bool libssig_ocsp_buffer_valid(
    const unsigned char* data,
    size_t               len,
    bool                 required
);
libssig_status libssig_ocsp_authenticate(
    const libssig_ocsp_verify_params* params,
    X509*                             issuer,
    OCSP_BASICRESP*                   response
);
libssig_status libssig_ocsp_status_read(
    const libssig_ocsp_verify_params* params,
    OCSP_BASICRESP*                   basic,
    OCSP_CERTID*                      id,
    libssig_ocsp_result*              result
);
bool libssig_verify_ocsp_params_valid(const libssig_verify_params* params);
libssig_status libssig_verify_ocsp(
    const libssig_verify_params* params,
    libssig_verify_result*       result
);
#endif

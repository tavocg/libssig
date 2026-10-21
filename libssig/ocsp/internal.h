/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef LIBSSIG_OCSP_INTERNAL_H
#define LIBSSIG_OCSP_INTERNAL_H

#include <libssig/ocsp/ocsp.h>
#include <libssig/trust.h>
#include <openssl/ocsp.h>

libssig_status libssig_ocsp_certificate(
    const unsigned char* data,
    size_t               len,
    X509**               out_cert
);
bool           libssig_ocsp_issuer_valid(X509* cert, X509* issuer);
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

#endif

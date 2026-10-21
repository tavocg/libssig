/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef LIBSSIG_VALIDATION_H
#define LIBSSIG_VALIDATION_H

#include <libssig/ades.h>
#include <openssl/ocsp.h>

libssig_status libssig_validation_collect(
    CMS_ContentInfo*             cms,
    const libssig_sign_services* services,
    libssig_validation_data*     data
);
libssig_status libssig_validation_tsa_certs(
    PKCS7*                       token,
    const libssig_sign_services* services,
    STACK_OF(X509) * *chain
);

#endif

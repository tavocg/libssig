/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef LIBSSIG_VERIFY_INTERNAL_H
#define LIBSSIG_VERIFY_INTERNAL_H

#include <libssig/ades.h>
#include <libssig/time.h>
#include <libssig/trust.h>
#include <libssig/tsa.h>
#include <libssig/verify/verify.h>

libssig_status libssig_verify_trust_check(
    CMS_ContentInfo*             cms,
    const libssig_verify_params* params,
    const STACK_OF(X509) * roots,
    STACK_OF(X509) * certs,
    libssig_verify_result* result
);
libssig_status libssig_history_verify(
    CMS_ContentInfo*             cms,
    const libssig_verify_params* params,
    STACK_OF(ASN1_TYPE) * revocations,
    const STACK_OF(X509) * protected_certs,
    libssig_verify_result* result
);
libssig_status libssig_validation_verify(
    CMS_ContentInfo*             cms,
    const libssig_verify_params* params,
    STACK_OF(ASN1_TYPE) * revocations,
    const STACK_OF(X509) * protected_certs,
    bool                   historical,
    libssig_verify_result* result
);
void libssig_verify_profiles_detect(
    CMS_ContentInfo*       cms,
    bool                   pades,
    bool                   revocations,
    libssig_verify_result* result
);
void libssig_verify_profiles_upgrade(
    bool                   revocations,
    libssig_verify_result* result
);
void libssig_verify_profiles_finish(
    libssig_status         status,
    libssig_verify_result* result
);
bool libssig_verify_ocsp_params_valid(const libssig_verify_params* params);
libssig_status libssig_verify_ocsp(
    const libssig_verify_params* params,
    libssig_verify_result*       result
);
libssig_status libssig_verify_archives(
    CMS_ContentInfo*             cms,
    const libssig_verify_params* params,
    libssig_verify_result*       result
);
libssig_status libssig_pades_verify(
    const libssig_verify_params* params,
    libssig_verify_result*       result
);

#endif

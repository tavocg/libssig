/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef LIBSSIG_TSA_H
#define LIBSSIG_TSA_H

#include <libssig/hash.h>
#include <libssig/libssig.h>
#include <openssl/cms.h>
#include <openssl/ts.h>

libssig_status libssig_timestamp_response(
    const libssig_timestamp_params* params,
    TS_REQ*                         request,
    TS_RESP*                        response
);
bool            libssig_timestamp_time_valid(TS_TST_INFO* info);
TS_MSG_IMPRINT* libssig_timestamp_imprint_create(
    CMS_SignerInfo* signer,
    const EVP_MD*   digest
);
bool libssig_timestamp_imprint_matches(
    TS_MSG_IMPRINT* imprint,
    CMS_SignerInfo* signer
);

libssig_status libssig_verify_timestamps(
    CMS_ContentInfo*             cms,
    const libssig_verify_params* params,
    libssig_verify_result*       result
);
libssig_status libssig_verify_timestamp_token(
    CMS_ContentInfo*             token,
    const libssig_verify_params* params,
    const EVP_MD*                digest,
    const unsigned char*         imprint,
    size_t                       imprint_len,
    libssig_verify_timestamp*    result
);

#endif

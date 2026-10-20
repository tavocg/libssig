/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef LIBSSIG_TIMESTAMP_INTERNAL_H
#define LIBSSIG_TIMESTAMP_INTERNAL_H

#include <libssig/verify_internal.h>
#include <openssl/ts.h>

libssig_status libssig_timestamp_container(
    const unsigned char* data,
    size_t               len,
    size_t               index,
    CMS_ContentInfo**    out_cms,
    CMS_SignerInfo**     out_signer
);
const EVP_MD* libssig_timestamp_digest(libssig_hash hash);
bool libssig_timestamp_imprint(TS_REQ* request, CMS_SignerInfo* signer);
libssig_status libssig_timestamp_response(
    const libssig_timestamp_params* params,
    TS_REQ*                         request,
    TS_RESP*                        response
);
#endif

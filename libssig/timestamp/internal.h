/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef LIBSSIG_TIMESTAMP_INTERNAL_H
#define LIBSSIG_TIMESTAMP_INTERNAL_H

#include <libssig/timestamp/timestamp.h>
#include <libssig/trust.h>
#include <libssig/tsa.h>

libssig_status libssig_timestamp_container(
    const unsigned char* data,
    size_t               len,
    size_t               index,
    CMS_ContentInfo**    out_cms,
    CMS_SignerInfo**     out_signer
);
bool libssig_timestamp_imprint(TS_REQ* request, CMS_SignerInfo* signer);

#endif

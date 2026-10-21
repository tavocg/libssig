/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef LIBSSIG_SERVICES_H
#define LIBSSIG_SERVICES_H

#include <libssig/libssig.h>
#include <libssig/tsa.h>

libssig_status libssig_ades_fetch(
    const libssig_sign_services* services,
    libssig_fetch_kind           kind,
    const char*                  url,
    const unsigned char*         data,
    size_t                       len,
    libssig_signature*           response
);
libssig_status libssig_ades_query(
    const unsigned char* imprint,
    size_t               len,
    libssig_hash         hash,
    libssig_signature*   output
);
libssig_status libssig_ades_response(
    const libssig_sign_services* services,
    const libssig_signature*     request,
    libssig_signature*           response
);
libssig_status libssig_ades_stamps(
    CMS_ContentInfo*             cms,
    const libssig_extend_params* params
);

#endif

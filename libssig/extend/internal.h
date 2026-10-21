/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef LIBSSIG_EXTEND_INTERNAL_H
#define LIBSSIG_EXTEND_INTERNAL_H

#include <libssig/ades.h>
#include <libssig/extend/extend.h>
#include <libssig/services.h>
#include <libssig/validation.h>

libssig_status libssig_cades_v131_archive_apply(
    CMS_ContentInfo**            cms,
    const libssig_extend_params* params
);
libssig_status libssig_pades_v121_extend(
    const libssig_extend_params* params,
    libssig_signature*           output
);

libssig_status libssig_cades_v131_extend(
    const libssig_extend_params* params,
    libssig_signature*           output
);
#endif

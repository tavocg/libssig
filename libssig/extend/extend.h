/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef LIBSSIG_EXTEND_EXTEND_H
#define LIBSSIG_EXTEND_EXTEND_H

#include <libssig/sign/sign.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Extend CAdES or a single-signature PDF without accessing a token. content is
 * required for detached signatures. B-LTA is the zero/default level; missing
 * services fail explicitly. Output is empty on failure. Existing signatures are
 * never downgraded. */
typedef struct {
	const unsigned char*         data;
	size_t                       data_len;
	const unsigned char*         content;
	size_t                       content_len;
	libssig_level                level;
	libssig_hash                 hash;
	const libssig_sign_services* services;
} libssig_extend_params;

libssig_status libssig_extend(
    const libssig_extend_params* params,
    libssig_signature*           signature
);

#ifdef __cplusplus
}
#endif

#endif

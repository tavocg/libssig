/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef LIBSSIG_MULTISIGN_H
#define LIBSSIG_MULTISIGN_H
#include <libssig/document.h>

/* Independent signature views. CMS views retain the original certificates,
 * revocations and algorithms; XML views retain each signature's namespaces. */
typedef struct {
	libssig_format     format;
	libssig_signature* parts;
	size_t             count, bytes;
	bool               collection;
} libssig_multisign;
void libssig_multisign_protected_view(libssig_signature*);
libssig_status libssig_multisign_read(
    const unsigned char*,
    size_t,
    libssig_multisign*
);
void           libssig_multisign_free(libssig_multisign*);
libssig_status libssig_multisign_merge(
    const libssig_multisign*,
    libssig_signature*
);
libssig_status libssig_multisign_content(
    const libssig_multisign*,
    const unsigned char*,
    size_t,
    libssig_signature*,
    bool*
);
void libssig_multisign_failure(
    const libssig_verify_params*,
    libssig_status,
    libssig_verify_result*
);
libssig_status libssig_verify_append(
    libssig_verify_result*,
    libssig_verify_result*
);
#endif

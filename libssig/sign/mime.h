/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef LIBSSIG_SIGN_MIME_H
#define LIBSSIG_SIGN_MIME_H

#include <libssig/types.h>

libssig_status libssig_mime_type_detect(
    const unsigned char* data,
    size_t               len,
    char**               out_type
);

#endif

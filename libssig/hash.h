/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef LIBSSIG_HASH_H
#define LIBSSIG_HASH_H

#include <libssig/types.h>
#include <openssl/evp.h>

const EVP_MD* libssig_timestamp_digest(libssig_hash hash);

#endif

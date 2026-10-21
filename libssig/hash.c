/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <libssig/hash.h>

const EVP_MD* libssig_timestamp_digest(libssig_hash hash) {
	switch (hash) {
	case LIBSSIG_HASH_SHA256:
		return EVP_sha256();
	case LIBSSIG_HASH_SHA384:
		return EVP_sha384();
	case LIBSSIG_HASH_SHA512:
		return EVP_sha512();
	default:
		return NULL;
	}
}

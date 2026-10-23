/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef LIBSSIG_TRUST_STORE_H
#define LIBSSIG_TRUST_STORE_H

/* Optional OpenSSL integration header; not needed by ordinary libssig users. */
#include <libssig/types.h>
#include <openssl/x509_vfy.h>
#ifdef __cplusplus
extern "C" {
#endif

/* Add OpenSSL default paths (including SSL_CERT_FILE/SSL_CERT_DIR), and native
 * system certificates on Windows/macOS. Add explicit anchors before this call
 * to preserve their independent trust. Native anchors additionally require
 * successful offline OS validation of the same chain, purpose and time.
 * Owns its native state until store is freed. Idempotent; do not replace its
 * verification callback afterward. On error discard the store. */
libssig_status libssig_trust_store_load_system(X509_STORE* store);

#ifdef __cplusplus
}
#endif
#endif

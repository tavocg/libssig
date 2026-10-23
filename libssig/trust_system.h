/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef LIBSSIG_TRUST_SYSTEM_H
#define LIBSSIG_TRUST_SYSTEM_H
#include <libssig/trust_store.h>
#include <openssl/x509v3.h>
#include <time.h>

#if defined(_WIN32) || defined(__APPLE__) || defined(LIBSSIG_TEST_NATIVE_TRUST)
#define LIBSSIG_NATIVE_TRUST 1
/* Append owned X509 references to the initially empty list. */
libssig_status libssig_trust_native_certificates(STACK_OF(X509) * certs);
/* Validate the exact OpenSSL chain using current OS trust settings, offline. */
bool libssig_trust_native_verify(X509_STORE_CTX* ctx);
/* DER adapters shared by both native implementations. */
libssig_status libssig_trust_native_append(
    STACK_OF(X509) * certs,
    const unsigned char* der,
    size_t               len
);
bool libssig_trust_native_matches(
    X509*                cert,
    const unsigned char* der,
    size_t               len
);
time_t libssig_trust_native_time(X509_STORE_CTX* ctx);
#endif
#endif

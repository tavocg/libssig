/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef TRUST_FIXTURE_H
#define TRUST_FIXTURE_H
#include <libssig/trust.h>
#include <libssig/trust_system.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#define CHECK(expr)                                                            \
	do {                                                                       \
		if (!(expr)) {                                                         \
			fprintf(stderr, "Failed: %s:%d: %s\n", __FILE__, __LINE__, #expr); \
			ERR_print_errors_fp(stderr);                                       \
			abort();                                                           \
		}                                                                      \
	} while (0)

static bool extension_add(
    X509*       cert,
    X509*       issuer,
    int         nid,
    const char* value
) {
	X509V3_CTX ctx;
	X509V3_set_ctx(&ctx, issuer, cert, NULL, NULL, 0);
	X509_EXTENSION* ext = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
	bool            ok = ext && X509_add_ext(cert, ext, -1);
	X509_EXTENSION_free(ext);
	return ok;
}
static X509* certificate(
    EVP_PKEY* key,
    long      serial,
    X509*     issuer,
    bool      ca,
    bool      tsa,
    bool      expired
) {
	X509* cert = X509_new();
	CHECK(
	    cert && X509_set_version(cert, 2) &&
	    ASN1_INTEGER_set(X509_get_serialNumber(cert), serial) &&
	    X509_set_pubkey(cert, key)
	);
	char name[64];
	snprintf(name, sizeof(name), "CRSign test %ld", serial);
	CHECK(X509_NAME_add_entry_by_txt(
	    X509_get_subject_name(cert),
	    "CN",
	    MBSTRING_ASC,
	    (const unsigned char*)name,
	    -1,
	    -1,
	    0
	));
	CHECK(
	    X509_set_issuer_name(
	        cert,
	        X509_get_subject_name(issuer ? issuer : cert)
	    ) &&
	    X509_gmtime_adj(X509_getm_notBefore(cert), expired ? -7200 : -86400) &&
	    X509_gmtime_adj(X509_getm_notAfter(cert), expired ? -3600 : 86400) &&
	    extension_add(
	        cert,
	        issuer ? issuer : cert,
	        NID_basic_constraints,
	        ca ? "critical,CA:TRUE" : "critical,CA:FALSE"
	    ) &&
	    extension_add(
	        cert,
	        issuer ? issuer : cert,
	        NID_key_usage,
	        ca ? "critical,keyCertSign,cRLSign" : "critical,digitalSignature"
	    )
	);
	if (tsa) {
		CHECK(extension_add(
		    cert,
		    issuer,
		    NID_ext_key_usage,
		    "critical,timeStamping"
		));
	}
	CHECK(X509_sign(cert, key, EVP_sha256()));
	return cert;
}
static int verify(
    X509_STORE*           store,
    X509*                 cert,
    int                   purpose,
    time_t                at,
    int*                  error,
    libssig_trust_anchor* anchor
) {
	X509_STORE_CTX* ctx = X509_STORE_CTX_new();
	CHECK(ctx && X509_STORE_CTX_init(ctx, store, cert, NULL));
	if (purpose) {
		CHECK(X509_STORE_CTX_set_purpose(ctx, purpose));
	}
	if (at) {
		X509_STORE_CTX_set_time(ctx, 0, at);
	}
	int result = X509_verify_cert(ctx);
	*error = X509_STORE_CTX_get_error(ctx);
	if (anchor) {
		libssig_trust_anchor_get(ctx, anchor);
	}
	X509_STORE_CTX_free(ctx);
	return result;
}
#endif

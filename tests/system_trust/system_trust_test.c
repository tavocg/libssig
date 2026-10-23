/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "fixture.h"
#include <openssl/pem.h>

static STACK_OF(X509) * native_certs;
static int     enumerations, validations, last_purpose, callbacks;
static time_t  last_time;
static bool    deny, fail_load;
libssig_status libssig_trust_native_certificates(STACK_OF(X509) * certs) {
	++enumerations;
	if (fail_load) {
		return LIBSSIG_ERROR_TRUST;
	}
	return libssig_verify_certs_append(certs, native_certs);
}
bool libssig_trust_native_verify(X509_STORE_CTX* ctx) {
	++validations;
	last_purpose = X509_VERIFY_PARAM_get_purpose(
	    X509_STORE_CTX_get0_param(ctx)
	);
	last_time = libssig_trust_native_time(ctx);
	return !deny;
}
static int previous_callback(int ok, X509_STORE_CTX* ctx) {
	(void)ctx;
	++callbacks;
	return ok;
}
static X509_STORE* create(unsigned int options, X509* explicit_root) {
	libssig_verify_params params = {.options = options};
	STACK_OF(X509)* roots = sk_X509_new_null();
	CHECK(roots);
	if (explicit_root) {
		CHECK(sk_X509_push(roots, explicit_root));
	}
	X509_STORE* store = NULL;
	CHECK(libssig_verify_store_create(&params, roots, &store) == LIBSSIG_OK);
	sk_X509_free(roots);
	return store;
}
int main(void) {
	EVP_PKEY* key = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", 2048);
	CHECK(key);
	X509* root = certificate(key, 1, NULL, true, false, false);
	X509* intermediate = certificate(key, 2, root, true, false, false);
	X509* leaf = certificate(key, 3, intermediate, false, false, false);
	X509* tsa = certificate(key, 4, intermediate, false, true, false);
	X509* expired = certificate(key, 5, intermediate, false, false, true);
	native_certs = sk_X509_new_null();
	CHECK(
	    native_certs && sk_X509_push(native_certs, root) &&
	    sk_X509_push(native_certs, intermediate)
	);
	int                  error;
	libssig_trust_anchor anchor;
	CHECK(libssig_trust_store_load_system(NULL) == LIBSSIG_ERROR_ARGUMENT);
	X509_STORE* store = create(0, NULL);
	CHECK(
	    verify(store, leaf, 0, 0, &error, NULL) != 1 && !enumerations &&
	    !validations
	);
	X509_STORE_free(store);

	store = create(LIBSSIG_VERIFY_SYSTEM_TRUST, NULL);
	CHECK(enumerations == 1);
	CHECK(
	    libssig_trust_store_load_system(store) == LIBSSIG_OK &&
	    enumerations == 1
	);
	CHECK(
	    verify(store, leaf, 0, 0, &error, &anchor) == 1 && error == X509_V_OK
	);
	CHECK(validations == 1 && anchor.source == LIBSSIG_TRUST_SYSTEM);
	CHECK(last_time >= time(NULL) - 2);
	deny = true;
	CHECK(
	    verify(store, leaf, 0, 0, &error, NULL) != 1 &&
	    error == X509_V_ERR_CERT_REJECTED
	);
	/* Embedded roots must not rescue a native policy rejection. */
	BIO* pem = BIO_new(BIO_s_mem());
	CHECK(pem && PEM_write_bio_X509(pem, root));
	char*                 bytes = NULL;
	long                  length = BIO_get_mem_data(pem, &bytes);
	libssig_verify_params fallback_params = {
	    .options = LIBSSIG_VERIFY_SYSTEM_TRUST,
	    .fallback_ca_data = (const unsigned char*)bytes,
	    .fallback_ca_data_len = (size_t)length
	};
	STACK_OF(X509)* empty = sk_X509_new_null();
	X509_STORE* fallback_store = NULL;
	CHECK(
	    empty &&
	    libssig_verify_store_create(&fallback_params, empty, &fallback_store) ==
	        LIBSSIG_OK
	);
	CHECK(
	    verify(fallback_store, leaf, 0, 0, &error, NULL) != 1 &&
	    error == X509_V_ERR_CERT_REJECTED
	);
	X509_STORE_free(fallback_store);
	sk_X509_free(empty);
	BIO_free(pem);
	deny = false;
	CHECK(
	    verify(store, tsa, X509_PURPOSE_TIMESTAMP_SIGN, 0, &error, NULL) == 1
	);
	CHECK(last_purpose == X509_PURPOSE_TIMESTAMP_SIGN);
	int checked = validations;
	CHECK(
	    verify(store, leaf, X509_PURPOSE_TIMESTAMP_SIGN, 0, &error, NULL) != 1
	);
	CHECK(error == X509_V_ERR_INVALID_PURPOSE && validations == checked);
	CHECK(verify(store, expired, 0, 0, &error, NULL) != 1);
	CHECK(error == X509_V_ERR_CERT_HAS_EXPIRED && validations == checked);
	time_t historical = time(NULL) - 5400;
	CHECK(
	    verify(store, expired, 0, historical, &error, NULL) == 1 &&
	    last_time == historical
	);
	X509_STORE_free(store);

	/* An explicit anchor is independent even if it also exists natively. */
	deny = true;
	checked = validations;
	store = create(LIBSSIG_VERIFY_SYSTEM_TRUST, root);
	CHECK(verify(store, leaf, 0, 0, &error, &anchor) == 1);
	CHECK(validations == checked && anchor.source == LIBSSIG_TRUST_ADDITIONAL);
	X509_STORE_free(store);
	deny = false;
	/* An intermediate in a native collection must never become a trusted root.
	 */
	CHECK(sk_X509_delete(native_certs, 0) == root);
	store = create(LIBSSIG_VERIFY_SYSTEM_TRUST, NULL);
	checked = validations;
	CHECK(
	    verify(store, leaf, 0, 0, &error, NULL) != 1 && validations == checked
	);
	X509_STORE_free(store);
	CHECK(sk_X509_push(native_certs, root));

	/* Existing callbacks survive installation and still see OpenSSL failures.
	 */
	store = X509_STORE_new();
	CHECK(store);
	X509_STORE_set_verify_cb(store, previous_callback);
	CHECK(libssig_trust_store_load_system(store) == LIBSSIG_OK);
	CHECK(verify(store, leaf, 0, 0, &error, NULL) == 1 && callbacks > 0);
	X509_STORE_free(store);
	fail_load = true;
	store = X509_STORE_new();
	CHECK(libssig_trust_store_load_system(store) == LIBSSIG_ERROR_TRUST);
	X509_STORE_free(store);

	unsigned char* der = NULL;
	int            len = i2d_X509(root, &der);
	CHECK(len > 0 && libssig_trust_native_matches(root, der, (size_t)len));
	CHECK(!libssig_trust_native_matches(leaf, der, (size_t)len));
	CHECK(
	    libssig_trust_native_append(native_certs, der, (size_t)len - 1) ==
	    LIBSSIG_ERROR_FORMAT
	);
	CHECK(!libssig_trust_native_matches(root, NULL, 0));
	OPENSSL_free(der);
	sk_X509_free(native_certs);
	X509_free(root);
	X509_free(intermediate);
	X509_free(leaf);
	X509_free(tsa);
	X509_free(expired);
	EVP_PKEY_free(key);
	puts(
	    "Native trust policy, purpose, time and explicit-anchor checks passed"
	);
	return 0;
}

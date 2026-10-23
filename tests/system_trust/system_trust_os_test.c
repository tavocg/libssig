/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "fixture.h"

int main(void) {
	X509_STORE* store = X509_STORE_new();
	CHECK(store && libssig_trust_store_load_system(store) == LIBSSIG_OK);
	STACK_OF(X509_OBJECT)* objects = X509_STORE_get1_objects(store);
	int error, accepted = 0;
	for (int i = 0; i < sk_X509_OBJECT_num(objects) && !accepted; ++i) {
		X509* cert = X509_OBJECT_get0_X509(sk_X509_OBJECT_value(objects, i));
		if (cert && X509_check_ca(cert) > 0 &&
		    verify(store, cert, 0, 0, &error, NULL) == 1) {
			++accepted;
		}
	}
	sk_X509_OBJECT_pop_free(objects, X509_OBJECT_free);
	CHECK(accepted > 0); /* Exercise actual OS policy evaluation without
	                        installing certificates. */
	EVP_PKEY* key = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", 2048);
	CHECK(key);
	X509* unknown = certificate(key, 100, NULL, true, false, false);
	CHECK(verify(store, unknown, 0, 0, &error, NULL) != 1);
	X509_STORE_free(store);
	store = X509_STORE_new();
	CHECK(store && X509_STORE_add_cert(store, unknown));
	CHECK(libssig_trust_store_load_system(store) == LIBSSIG_OK);
	CHECK(verify(store, unknown, 0, 0, &error, NULL) == 1);
	X509_STORE_free(store);
	X509_free(unknown);
	EVP_PKEY_free(key);
	return 0;
}

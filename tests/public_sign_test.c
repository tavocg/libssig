/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <libssig/libssig.h>
#include <stdio.h>
#include <stdlib.h>

#define CHECK(expr)                                                            \
	do {                                                                       \
		if (!(expr)) {                                                         \
			fprintf(stderr, "Failed: %s:%d: %s\n", __FILE__, __LINE__, #expr); \
			return 1;                                                          \
		}                                                                      \
	} while (0)

int main(void) {
	libssig_context     ctx = {0};
	libssig_sign_params params = {0};
	libssig_signature   signature = {0};
	CHECK(params.algo == LIBSSIG_ALGO_RSA_PKCS);
	CHECK(params.hash == LIBSSIG_HASH_SHA256);
	CHECK(params.format == LIBSSIG_FORMAT_CADES);
	CHECK(libssig_sign(NULL, &params, &signature) == LIBSSIG_ERROR_ARGUMENT);
	CHECK(libssig_sign(&ctx, NULL, &signature) == LIBSSIG_ERROR_ARGUMENT);
	CHECK(libssig_sign(&ctx, &params, NULL) == LIBSSIG_ERROR_ARGUMENT);
	CHECK(libssig_sign(&ctx, &params, &signature) == LIBSSIG_ERROR_ARGUMENT);
	CHECK(!signature.data && !signature.len && !signature.ck_rv);
	signature.data = malloc(8);
	CHECK(signature.data);
	signature.len = 8;
	signature.ck_rv = 1;
	libssig_signature_free(&signature);
	CHECK(!signature.data && !signature.len && !signature.ck_rv);
	libssig_signature_free(&signature);
	libssig_signature_free(NULL);
	return 0;
}

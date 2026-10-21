/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "internal.h"
#include <libssig/trust.h>

static libssig_status signer_trust_check(
    CMS_SignerInfo* s,
    X509_STORE*     store,
    STACK_OF(X509) * certs,
    libssig_verify_signer* signer
) {
	X509* cert = NULL;
	CMS_SignerInfo_get0_algs(s, NULL, &cert, NULL, NULL);
	X509_STORE_CTX* ctx = X509_STORE_CTX_new();
	if (!ctx || !X509_STORE_CTX_init(ctx, store, cert, certs)) {
		X509_STORE_CTX_free(ctx);
		return LIBSSIG_ERROR_CRYPTO;
	}

	/* Document signatures do not imply S/MIME certificate purpose. */
	int ok = X509_verify_cert(ctx);
	signer->trust_error = X509_STORE_CTX_get_error(ctx);
	X509_STORE_CTX_free(ctx);
	return ok == 1 ? LIBSSIG_OK : LIBSSIG_ERROR_TRUST;
}

libssig_status libssig_verify_trust_check(
    CMS_ContentInfo*             cms,
    const libssig_verify_params* params,
    const STACK_OF(X509) * roots,
    STACK_OF(X509) * certs,
    libssig_verify_result* result
) {
	X509_STORE*    store = NULL;
	libssig_status status = libssig_verify_store_create(params, roots, &store);
	if (status != LIBSSIG_OK) {
		X509_STORE_free(store);
		return status;
	}

	STACK_OF(CMS_SignerInfo)* signers = CMS_get0_SignerInfos(cms);
	result->trust_checked = true;
	result->trusted = true;
	for (size_t i = 0; i < result->count; ++i) {
		libssig_status checked = signer_trust_check(
		    sk_CMS_SignerInfo_value(signers, (int)i),
		    store,
		    certs,
		    &result->signers[i]
		);
		if (checked != LIBSSIG_OK) {
			result->trusted = false;
			status = checked;
			if (checked != LIBSSIG_ERROR_TRUST) {
				break;
			}
		}
	}
	X509_STORE_free(store);
	return status;
}

/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "internal.h"
#include <libssig/document.h>

libssig_status libssig_document_validate(
    X509*                          cert,
    const libssig_validation_data* evidence,
    const libssig_verify_params*   params,
    libssig_verify_result*         result
) {
	libssig_verify_signer* signer = &result->signers[0];
	bool automatic = !(params->options & LIBSSIG_VERIFY_CURRENT_TIME);
	bool historical = (params->options & LIBSSIG_VERIFY_HISTORICAL) ||
	                  (automatic && signer->level == LIBSSIG_LEVEL_B_LTA);
	if (historical && (params->ocsp_count ||
	                   (params->options & (LIBSSIG_VERIFY_REQUIRE_OCSP |
	                                       LIBSSIG_VERIFY_REQUIRE_TSA_OCSP)))) {
		return LIBSSIG_ERROR_ARGUMENT;
	}
	if (historical && signer->level != LIBSSIG_LEVEL_B_LTA) {
		return LIBSSIG_ERROR_EVIDENCE;
	}
	if (historical || (automatic && signer->level == LIBSSIG_LEVEL_B_LT)) {
		libssig_status explicit_ocsp = libssig_verify_ocsp(params, result);
		if (explicit_ocsp != LIBSSIG_OK) {
			return explicit_ocsp;
		}
		return libssig_document_evidence_verify(
		    cert,
		    evidence,
		    params,
		    result,
		    historical
		);
	}
	libssig_status status = LIBSSIG_OK;
	if (params->ca_data || (params->options & LIBSSIG_VERIFY_SYSTEM_TRUST)) {
		STACK_OF(X509)* roots = NULL;
		X509_STORE*     store = NULL;
		X509_STORE_CTX* ctx = X509_STORE_CTX_new();
		status = libssig_verify_certs_parse(
		    params->ca_data,
		    params->ca_data_len,
		    &roots
		);
		if (status == LIBSSIG_OK) {
			status = libssig_verify_store_create(params, roots, &store);
		}
		if (status == LIBSSIG_OK) {
			result->trust_checked = true;
			bool ok = ctx &&
			          X509_STORE_CTX_init(ctx, store, cert, evidence->certs) &&
			          X509_verify_cert(ctx) == 1;
			signer->trust_error = ctx ? X509_STORE_CTX_get_error(ctx)
			                          : X509_V_ERR_OUT_OF_MEM;
			result->trusted = ok;
			if (ok) {
				libssig_trust_anchor_get(ctx, &signer->anchor);
			}
			if (!ok) {
				status = LIBSSIG_ERROR_TRUST;
			}
		}
		X509_STORE_CTX_free(ctx);
		X509_STORE_free(store);
		sk_X509_pop_free(roots, X509_free);
	}
	if ((params->options & LIBSSIG_VERIFY_REQUIRE_TIMESTAMP) &&
	    !signer->timestamp.valid) {
		return LIBSSIG_ERROR_TIMESTAMP;
	}
	libssig_status revocation = libssig_verify_ocsp(params, result);
	return revocation == LIBSSIG_OK ? status : revocation;
}

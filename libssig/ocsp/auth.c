/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "internal.h"
#include <openssl/err.h>

static bool delegated_usage_valid(X509* cert) {
	int critical = -1;
	EXTENDED_KEY_USAGE*
	     usage = X509_get_ext_d2i(cert, NID_ext_key_usage, &critical, NULL);
	bool found = false;
	for (int i = 0; i < sk_ASN1_OBJECT_num(usage); ++i) {
		if (OBJ_obj2nid(sk_ASN1_OBJECT_value(usage, i)) == NID_OCSP_sign) {
			found = true;
		}
	}
	EXTENDED_KEY_USAGE_free(usage);
	if (!found) {
		return false;
	}

	critical = -1;
	ASN1_BIT_STRING*
	     bits = X509_get_ext_d2i(cert, NID_key_usage, &critical, NULL);
	bool ok = bits ? ASN1_BIT_STRING_get_bit(bits, 0) == 1 : critical == -1;
	ASN1_BIT_STRING_free(bits);
	return ok;
}

static bool responder_authorized(
    OCSP_BASICRESP* response,
    STACK_OF(X509) * certs,
    X509* issuer
) {
	X509* signer = NULL;
	if (!OCSP_resp_get0_signer(response, &signer, certs) || !signer) {
		return false;
	}
	return X509_cmp(signer, issuer) == 0 ||
	       (libssig_ocsp_issuer_valid(signer, issuer) &&
	        delegated_usage_valid(signer));
}

static libssig_status issuer_trust_check(
    X509* issuer,
    STACK_OF(X509) * certs,
    X509_STORE* store
) {
	X509_STORE_CTX* ctx = X509_STORE_CTX_new();
	if (!ctx || !X509_STORE_CTX_init(ctx, store, issuer, certs)) {
		X509_STORE_CTX_free(ctx);
		return LIBSSIG_ERROR_CRYPTO;
	}
	int ok = X509_verify_cert(ctx);
	X509_STORE_CTX_free(ctx);
	return ok == 1 ? LIBSSIG_OK : LIBSSIG_ERROR_TRUST;
}

static libssig_status verify_error(void) {
	libssig_status status = LIBSSIG_ERROR_VERIFY;
	unsigned long  error;
	while ((error = ERR_get_error()) != 0) {
		if (ERR_GET_LIB(error) == ERR_LIB_OCSP &&
		    ERR_GET_REASON(error) == OCSP_R_CERTIFICATE_VERIFY_ERROR) {
			status = LIBSSIG_ERROR_TRUST;
		}
	}
	return status;
}

libssig_status libssig_ocsp_authenticate(
    const libssig_ocsp_verify_params* params,
    X509*                             issuer,
    OCSP_BASICRESP*                   response
) {
	STACK_OF(X509)* roots = NULL, *certs = NULL;
	X509_STORE*    store = NULL;
	libssig_status status = libssig_verify_certs_parse(
	    params->ca_data,
	    params->ca_data_len,
	    &roots
	);
	if (status == LIBSSIG_OK) {
		status = libssig_verify_certs_parse(
		    params->intermediates_data,
		    params->intermediates_data_len,
		    &certs
		);
	}

	if (status == LIBSSIG_OK) {
		if (!X509_up_ref(issuer)) {
			status = LIBSSIG_ERROR_MEMORY;
		} else if (!sk_X509_push(certs, issuer)) {
			X509_free(issuer);
			status = LIBSSIG_ERROR_MEMORY;
		}
	}

	if (status == LIBSSIG_OK) {
		libssig_verify_params trust = {
		    .fallback_ca_data = params->fallback_ca_data,
		    .fallback_ca_data_len = params->fallback_ca_data_len,
		    .options = (params->options & LIBSSIG_OCSP_SYSTEM_TRUST)
		                   ? LIBSSIG_VERIFY_SYSTEM_TRUST
		                   : 0,
		};
		status = libssig_verify_store_create(&trust, roots, &store);
	}

	if (status == LIBSSIG_OK &&
	    !responder_authorized(response, certs, issuer)) {
		status = LIBSSIG_ERROR_VERIFY;
	}

	if (status == LIBSSIG_OK) {
		status = issuer_trust_check(issuer, certs, store);
	}

	if (status == LIBSSIG_OK) {
		ERR_clear_error();
		if (OCSP_basic_verify(response, certs, store, OCSP_NOEXPLICIT) != 1) {
			status = verify_error();
		}
	}
	X509_STORE_free(store);
	sk_X509_pop_free(roots, X509_free);
	sk_X509_pop_free(certs, X509_free);
	return status;
}

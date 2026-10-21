/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "internal.h"
#include <libssig/document.h>
#include <limits.h>
#include <openssl/cms.h>
#include <openssl/cmserr.h>
#include <openssl/err.h>
#include <openssl/ess.h>
#include <openssl/x509v3.h>
#include <stdlib.h>
#include <string.h>

void libssig_verify_free(libssig_verify_result* result) {
	if (!result) {
		return;
	}

	for (size_t i = 0; i < result->count; ++i) {
		free(result->signers[i].cert_der);
		free(result->signers[i].mime_type);
		free(result->signers[i].timestamp.cert_der);
		free(result->signers[i].archive.cert_der);
	}
	free(result->signers);
	*result = (libssig_verify_result){0};
}

static bool bundle_valid(const unsigned char* data, size_t len) {
	return len <= INT_MAX && ((data && len) || (!data && !len));
}

static bool current_evidence_valid(const libssig_verify_params* params) {
	if (params->current_revocation_count > 1024 ||
	    (!params->current_revocations && params->current_revocation_count) ||
	    (params->current_revocation_count &&
	     (params->options & LIBSSIG_VERIFY_CURRENT_TIME))) {
		return false;
	}
	for (size_t i = 0; i < params->current_revocation_count; ++i) {
		const libssig_revocation_evidence* item = &params
		                                               ->current_revocations[i];
		if (!item->data || !item->len || item->len > 16 * 1024 * 1024) {
			return false;
		}
	}
	return true;
}

libssig_status libssig_verify(
    const libssig_verify_params* params,
    libssig_verify_result*       result
) {
	if (!result) {
		return LIBSSIG_ERROR_ARGUMENT;
	}

	*result = (libssig_verify_result){0};
	if (!params || !current_evidence_valid(params) ||
	    !libssig_verify_ocsp_params_valid(params) || !params->data ||
	    !params->data_len || params->data_len > LONG_MAX ||
	    params->content_len > INT_MAX ||
	    (!params->content && params->content_len) ||
	    (params->options &
	     ~(LIBSSIG_VERIFY_SYSTEM_TRUST | LIBSSIG_VERIFY_TSA_SYSTEM_TRUST |
	       LIBSSIG_VERIFY_REQUIRE_TIMESTAMP | LIBSSIG_VERIFY_REQUIRE_OCSP |
	       LIBSSIG_VERIFY_REQUIRE_TSA_OCSP | LIBSSIG_VERIFY_HISTORICAL |
	       LIBSSIG_VERIFY_CURRENT_TIME)) ||
	    !bundle_valid(params->fallback_ca_data, params->fallback_ca_data_len) ||
	    !bundle_valid(
	        params->tsa_fallback_ca_data,
	        params->tsa_fallback_ca_data_len
	    ) ||
	    (params->fallback_ca_data && !params->ca_data &&
	     !(params->options & LIBSSIG_VERIFY_SYSTEM_TRUST)) ||
	    (params->tsa_fallback_ca_data && !params->tsa_ca_data &&
	     !(params->options & LIBSSIG_VERIFY_TSA_SYSTEM_TRUST)) ||
	    !bundle_valid(params->ca_data, params->ca_data_len) ||
	    !bundle_valid(
	        params->intermediates_data,
	        params->intermediates_data_len
	    ) ||
	    !bundle_valid(params->tsa_ca_data, params->tsa_ca_data_len) ||
	    !bundle_valid(
	        params->tsa_intermediates_data,
	        params->tsa_intermediates_data_len
	    ) ||
	    (params->tsa_intermediates_data && !params->tsa_ca_data &&
	     !(params->options & LIBSSIG_VERIFY_TSA_SYSTEM_TRUST)) ||
	    (params->intermediates_data && !params->ca_data &&
	     !(params->options & LIBSSIG_VERIFY_SYSTEM_TRUST))) {
		return LIBSSIG_ERROR_ARGUMENT;
	}

	if ((params->options & LIBSSIG_VERIFY_HISTORICAL) &&
	    (params->options & LIBSSIG_VERIFY_CURRENT_TIME)) {
		return LIBSSIG_ERROR_ARGUMENT;
	}

	if ((params->options & LIBSSIG_VERIFY_HISTORICAL) &&
	    ((!params->ca_data &&
	      !(params->options & LIBSSIG_VERIFY_SYSTEM_TRUST)) ||
	     (!params->tsa_ca_data &&
	      !(params->options & LIBSSIG_VERIFY_TSA_SYSTEM_TRUST)) ||
	     params->ocsp_count ||
	     (params->options &
	      (LIBSSIG_VERIFY_REQUIRE_OCSP | LIBSSIG_VERIFY_REQUIRE_TSA_OCSP)))) {
		return LIBSSIG_ERROR_ARGUMENT;
	}

	libssig_format format = libssig_document_format(
	    params->data,
	    params->data_len
	);
	if (format == LIBSSIG_FORMAT_JADES || format == LIBSSIG_FORMAT_XADES) {
		libssig_status status = format == LIBSSIG_FORMAT_JADES
		                            ? libssig_jades_v121_verify(params, result)
		                            : libssig_xades_v131_verify(params, result);
		if (status != LIBSSIG_OK && status != LIBSSIG_ERROR_TRUST &&
		    status != LIBSSIG_ERROR_TIMESTAMP && status != LIBSSIG_ERROR_OCSP &&
		    status != LIBSSIG_ERROR_REVOKED &&
		    status != LIBSSIG_ERROR_EVIDENCE) {
			libssig_verify_free(result);
		}
		return status;
	}
	if (params->data_len >= 5 && !memcmp(params->data, "%PDF-", 5)) {
		libssig_status status = libssig_pades_v121_verify(params, result);
		libssig_verify_profiles_finish(status, result);
		if (status != LIBSSIG_OK && status != LIBSSIG_ERROR_TRUST &&
		    status != LIBSSIG_ERROR_TIMESTAMP && status != LIBSSIG_ERROR_OCSP &&
		    status != LIBSSIG_ERROR_REVOKED &&
		    status != LIBSSIG_ERROR_EVIDENCE) {
			libssig_verify_free(result);
		}
		return status;
	}

	return libssig_cades_v131_verify(params, result);
}

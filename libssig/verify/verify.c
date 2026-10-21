/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "internal.h"
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

static libssig_status mime_copy(CMS_SignerInfo* s, char** out_type) {
	ASN1_OBJECT* oid = OBJ_txt2obj("0.4.0.1733.2.1", 1);
	if (!oid) {
		return LIBSSIG_ERROR_MEMORY;
	}

	int i = CMS_signed_get_attr_by_OBJ(s, oid, -1);
	int next = i < 0 ? -1 : CMS_signed_get_attr_by_OBJ(s, oid, i);
	ASN1_OBJECT_free(oid);
	if (i < 0) {
		return LIBSSIG_OK;
	}

	X509_ATTRIBUTE* attr = CMS_signed_get_attr(s, i);
	if (next >= 0 || X509_ATTRIBUTE_count(attr) != 1) {
		return LIBSSIG_ERROR_VERIFY;
	}

	ASN1_TYPE* value = X509_ATTRIBUTE_get0_type(attr, 0);
	if (!value || value->type != V_ASN1_UTF8STRING) {
		return LIBSSIG_ERROR_VERIFY;
	}

	int                  len = ASN1_STRING_length(value->value.utf8string);
	const unsigned char* data = ASN1_STRING_get0_data(value->value.utf8string);
	if (len <= 0 || len > 255 || memchr(data, 0, (size_t)len)) {
		return LIBSSIG_ERROR_VERIFY;
	}

	for (int i = 0; i < len; ++i) {
		if (data[i] < 0x20 || data[i] > 0x7e) {
			return LIBSSIG_ERROR_VERIFY;
		}
	}

	*out_type = malloc((size_t)len + 1);
	if (!*out_type) {
		return LIBSSIG_ERROR_MEMORY;
	}
	memcpy(*out_type, data, (size_t)len);
	(*out_type)[len] = '\0';
	return LIBSSIG_OK;
}

static libssig_status signer_copy(
    CMS_SignerInfo* s,
    STACK_OF(X509) * certs,
    libssig_verify_signer* signer
) {
	X509* cert = NULL;
	CMS_SignerInfo_get0_algs(s, NULL, &cert, NULL, NULL);
	if (!cert || !libssig_verify_ess_check(s, cert, certs)) {
		return LIBSSIG_ERROR_VERIFY;
	}

	int len = i2d_X509(cert, NULL);
	if (len <= 0) {
		return LIBSSIG_ERROR_CRYPTO;
	}

	signer->cert_der = malloc((size_t)len);
	if (!signer->cert_der) {
		return LIBSSIG_ERROR_MEMORY;
	}

	unsigned char* cursor = signer->cert_der;
	if (i2d_X509(cert, &cursor) != len) {
		return LIBSSIG_ERROR_CRYPTO;
	}
	signer->cert_der_len = (size_t)len;
	return mime_copy(s, &signer->mime_type);
}

static libssig_status signature_error(void) {
	libssig_status status = LIBSSIG_ERROR_VERIFY;
	unsigned long  error;
	while ((error = ERR_get_error()) != 0) {
		int reason = ERR_GET_REASON(error);
		if ((ERR_GET_LIB(error) == ERR_LIB_CMS &&
		     (reason == CMS_R_UNKNOWN_DIGEST_ALGORITHM
#ifdef CMS_R_UNSUPPORTED_SIGNATURE_ALGORITHM
		      || reason == CMS_R_UNSUPPORTED_SIGNATURE_ALGORITHM
#endif
)) ||
		    reason == ERR_R_UNSUPPORTED) {
			status = LIBSSIG_ERROR_UNSUPPORTED;
		}
	}
	return status;
}

static libssig_status signatures_check(
    CMS_ContentInfo*             cms,
    const libssig_verify_params* params,
    STACK_OF(X509) * certs,
    libssig_verify_result* result
) {
	result->detached = CMS_is_detached(cms) == 1;
	if (result->detached && !params->content) {
		return LIBSSIG_ERROR_CONTENT_REQUIRED;
	}

	if (!result->detached && params->content) {
		return LIBSSIG_ERROR_ARGUMENT;
	}

	BIO* input = result->detached ? BIO_new_mem_buf(
	                                    params->content,
	                                    (int)params->content_len
	                                )
	                              : NULL;
	if (result->detached && !input) {
		return LIBSSIG_ERROR_MEMORY;
	}

	ERR_clear_error();
	int ok = CMS_verify(
	    cms,
	    NULL,
	    NULL,
	    input,
	    NULL,
	    CMS_BINARY | CMS_NO_SIGNER_CERT_VERIFY
	);
	BIO_free(input);
	if (ok != 1) {
		return signature_error();
	}

	STACK_OF(CMS_SignerInfo)* signers = CMS_get0_SignerInfos(cms);
	int count = sk_CMS_SignerInfo_num(signers);
	if (count <= 0) {
		return LIBSSIG_ERROR_FORMAT;
	}

	result->signers = calloc((size_t)count, sizeof(*result->signers));
	if (!result->signers) {
		return LIBSSIG_ERROR_MEMORY;
	}
	result->count = (size_t)count;

	libssig_status status = LIBSSIG_OK;
	for (int i = 0; i < count && status == LIBSSIG_OK; ++i) {
		status = signer_copy(
		    sk_CMS_SignerInfo_value(signers, i),
		    certs,
		    &result->signers[i]
		);
	}
	result->signature_valid = status == LIBSSIG_OK;
	return status;
}

static libssig_status historical_run(
    CMS_ContentInfo*             cms,
    const libssig_verify_params* params,
    libssig_verify_result*       result,
    libssig_raw_cms*             raw
) {
	libssig_status status = libssig_verify_timestamps(cms, params, result);
	if (status == LIBSSIG_OK) {
		status = libssig_verify_archives(cms, params, result);
	}
	if (status == LIBSSIG_OK) {
		status = libssig_history_verify(
		    cms,
		    params,
		    raw->signed_data->revocations,
		    NULL,
		    result
		);
	} else {
		for (size_t i = 0; i < result->count; ++i) {
			result->signers[i].history = status == LIBSSIG_ERROR_TRUST
			                                 ? LIBSSIG_HISTORY_UNTRUSTED
			                                 : LIBSSIG_HISTORY_INCOMPLETE;
		}
	}
	return status;
}

static bool level_present(
    const libssig_verify_result* result,
    libssig_level                level
) {
	for (size_t i = 0; i < result->count; ++i) {
		if (result->signers[i].level == level &&
		    (result->signers[i].level_detected ||
		     level == LIBSSIG_LEVEL_B_LTA)) {
			return true;
		}
	}
	return false;
}

static libssig_raw_cms* raw_parse(CMS_ContentInfo* cms) {
	unsigned char*       data = NULL;
	int                  len = i2d_CMS_ContentInfo(cms, &data);
	const unsigned char* cursor = data;
	libssig_raw_cms*     raw = len > 0 ? d2i_libssig_raw_cms(NULL, &cursor, len)
	                                   : NULL;
	OPENSSL_free(data);
	return raw;
}

static libssig_status verification_run(
    CMS_ContentInfo*             cms,
    const libssig_verify_params* params,
    libssig_verify_result*       result
) {
	STACK_OF(X509)* roots = NULL;
	STACK_OF(X509)* certs = NULL;
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

	STACK_OF(X509)* embedded = CMS_get1_certs(cms);
	if (status == LIBSSIG_OK) {
		status = libssig_verify_certs_append(certs, embedded);
	}

	if (status == LIBSSIG_OK) {
		status = signatures_check(cms, params, certs, result);
	}

	libssig_raw_cms* raw = status == LIBSSIG_OK ? raw_parse(cms) : NULL;
	if (status == LIBSSIG_OK && !raw) {
		status = LIBSSIG_ERROR_CRYPTO;
	}
	if (status == LIBSSIG_OK) {
		libssig_verify_profiles_detect(
		    cms,
		    false,
		    sk_ASN1_TYPE_num(raw->signed_data->revocations) > 0,
		    result
		);
	}
	bool automatic = !(params->options & LIBSSIG_VERIFY_CURRENT_TIME);
	bool historical = (params->options & LIBSSIG_VERIFY_HISTORICAL) ||
	                  (automatic && level_present(result, LIBSSIG_LEVEL_B_LTA));
	if (status == LIBSSIG_OK && historical) {
		libssig_verify_params selected = *params;
		selected.options |= LIBSSIG_VERIFY_HISTORICAL;
		status = selected.ocsp_count ||
		                 (selected.options & (LIBSSIG_VERIFY_REQUIRE_OCSP |
		                                      LIBSSIG_VERIFY_REQUIRE_TSA_OCSP))
		             ? LIBSSIG_ERROR_ARGUMENT
		             : historical_run(cms, &selected, result, raw);
		libssig_raw_cms_free(raw);
		sk_X509_pop_free(embedded, X509_free);
		sk_X509_pop_free(certs, X509_free);
		sk_X509_pop_free(roots, X509_free);
		return status;
	}

	if (status == LIBSSIG_OK &&
	    (params->ca_data || (params->options & LIBSSIG_VERIFY_SYSTEM_TRUST))) {
		status = libssig_verify_trust_check(cms, params, roots, certs, result);
	}
	if (status == LIBSSIG_OK || status == LIBSSIG_ERROR_TRUST) {
		libssig_status stamps = libssig_verify_timestamps(cms, params, result);
		if (stamps != LIBSSIG_OK) {
			status = stamps;
		}
	}
	if (status == LIBSSIG_OK || status == LIBSSIG_ERROR_TRUST ||
	    status == LIBSSIG_ERROR_TIMESTAMP) {
		libssig_status revocation = libssig_verify_ocsp(params, result);
		if (revocation != LIBSSIG_OK && (status != LIBSSIG_ERROR_TIMESTAMP ||
		                                 revocation != LIBSSIG_ERROR_OCSP)) {
			status = revocation;
		}
	}
	if (status == LIBSSIG_OK || status == LIBSSIG_ERROR_TRUST) {
		libssig_status archive = libssig_verify_archives(cms, params, result);
		if (archive != LIBSSIG_OK) {
			status = archive;
		}
	}
	if (status == LIBSSIG_OK && automatic &&
	    level_present(result, LIBSSIG_LEVEL_B_LT)) {
		status = libssig_validation_verify(
		    cms,
		    params,
		    raw->signed_data->revocations,
		    NULL,
		    false,
		    result
		);
	}
	libssig_raw_cms_free(raw);
	sk_X509_pop_free(embedded, X509_free);
	sk_X509_pop_free(certs, X509_free);
	sk_X509_pop_free(roots, X509_free);
	return status;
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

	if (params->data_len >= 5 && !memcmp(params->data, "%PDF-", 5)) {
		libssig_status status = libssig_pades_verify(params, result);
		libssig_verify_profiles_finish(status, result);
		if (status != LIBSSIG_OK && status != LIBSSIG_ERROR_TRUST &&
		    status != LIBSSIG_ERROR_TIMESTAMP && status != LIBSSIG_ERROR_OCSP &&
		    status != LIBSSIG_ERROR_REVOKED &&
		    status != LIBSSIG_ERROR_EVIDENCE) {
			libssig_verify_free(result);
		}
		return status;
	}

	const unsigned char* cursor = params->data;
	CMS_ContentInfo*     cms = d2i_CMS_ContentInfo(
        NULL,
        &cursor,
        (long)params->data_len
    );
	if (!cms || cursor != params->data + params->data_len) {
		CMS_ContentInfo_free(cms);
		return LIBSSIG_ERROR_FORMAT;
	}

	libssig_status status = OBJ_obj2nid(CMS_get0_type(cms)) == NID_pkcs7_signed
	                            ? verification_run(cms, params, result)
	                            : LIBSSIG_ERROR_UNSUPPORTED;
	CMS_ContentInfo_free(cms);
	libssig_verify_profiles_finish(status, result);
	if (status != LIBSSIG_OK && status != LIBSSIG_ERROR_TRUST &&
	    status != LIBSSIG_ERROR_TIMESTAMP && status != LIBSSIG_ERROR_OCSP &&
	    status != LIBSSIG_ERROR_REVOKED && status != LIBSSIG_ERROR_EVIDENCE) {
		libssig_verify_free(result);
	}
	return status;
}

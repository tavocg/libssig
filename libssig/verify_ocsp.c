/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <libssig/ocsp_internal.h>
#include <limits.h>
#include <stdint.h>

bool libssig_verify_ocsp_params_valid(const libssig_verify_params* params) {
	if ((!params->ocsp && params->ocsp_count) ||
	    params->ocsp_count > SIZE_MAX / sizeof(*params->ocsp)) {
		return false;
	}
	bool doc_trust = params->ca_data ||
	                 (params->options & LIBSSIG_VERIFY_SYSTEM_TRUST);
	bool tsa_trust = params->tsa_ca_data ||
	                 (params->options & LIBSSIG_VERIFY_TSA_SYSTEM_TRUST);
	if (((params->options & LIBSSIG_VERIFY_REQUIRE_OCSP) && !doc_trust) ||
	    ((params->options & LIBSSIG_VERIFY_REQUIRE_TSA_OCSP) && !tsa_trust)) {
		return false;
	}
	for (size_t i = 0; i < params->ocsp_count; ++i) {
		const libssig_ocsp_evidence* item = &params->ocsp[i];
		if ((item->tsa ? !tsa_trust : !doc_trust) ||
		    !libssig_ocsp_buffer_valid(
		        item->issuer_data,
		        item->issuer_data_len,
		        true
		    ) ||
		    !libssig_ocsp_buffer_valid(
		        item->request,
		        item->request_len,
		        true
		    ) ||
		    !libssig_ocsp_buffer_valid(
		        item->response,
		        item->response_len,
		        false
		    ) ||
		    (item->options & ~LIBSSIG_OCSP_ALLOW_MISSING_NONCE) ||
		    item->max_age > LONG_MAX || item->clock_skew > LONG_MAX) {
			return false;
		}
		for (size_t j = 0; j < i; ++j) {
			if (item->signer_index == params->ocsp[j].signer_index &&
			    item->tsa == params->ocsp[j].tsa) {
				return false;
			}
		}
	}
	return true;
}

static libssig_status evidence_check(
    const libssig_verify_params* params,
    const libssig_ocsp_evidence* item,
    libssig_verify_signer*       signer
) {
	libssig_ocsp_result* result = item->tsa ? &signer->timestamp.ocsp
	                                        : &signer->ocsp;
	const unsigned char* cert = item->tsa ? signer->timestamp.cert_der
	                                      : signer->cert_der;
	size_t               len = item->tsa ? signer->timestamp.cert_der_len
	                                     : signer->cert_der_len;
	if (!item->response || !cert) {
		result->error = LIBSSIG_ERROR_OCSP;
		return LIBSSIG_ERROR_OCSP;
	}

	libssig_ocsp_verify_params verify = {
	    .cert_data = cert,
	    .cert_data_len = len,
	    .issuer_data = item->issuer_data,
	    .issuer_data_len = item->issuer_data_len,
	    .request = item->request,
	    .request_len = item->request_len,
	    .response = item->response,
	    .response_len = item->response_len,
	    .ca_data = item->tsa ? params->tsa_ca_data : params->ca_data,
	    .ca_data_len = item->tsa ? params->tsa_ca_data_len
	                             : params->ca_data_len,
	    .intermediates_data = item->tsa ? params->tsa_intermediates_data
	                                    : params->intermediates_data,
	    .intermediates_data_len = item->tsa ? params->tsa_intermediates_data_len
	                                        : params->intermediates_data_len,
	    .options = item->options,
	    .max_age = item->max_age,
	    .clock_skew = item->clock_skew,
	};
	unsigned int system = item->tsa ? LIBSSIG_VERIFY_TSA_SYSTEM_TRUST
	                                : LIBSSIG_VERIFY_SYSTEM_TRUST;
	if (params->options & system) {
		verify.options |= LIBSSIG_OCSP_SYSTEM_TRUST;
	}
	libssig_status status = libssig_ocsp_verify(&verify, result);
	if (status == LIBSSIG_ERROR_MEMORY || status == LIBSSIG_ERROR_CRYPTO) {
		return status;
	}

	if (result->valid && result->status == LIBSSIG_OCSP_REVOKED) {
		return LIBSSIG_ERROR_REVOKED;
	}
	return result->valid && result->status == LIBSSIG_OCSP_GOOD
	           ? LIBSSIG_OK
	           : LIBSSIG_ERROR_OCSP;
}

static libssig_status status_merge(
    libssig_status current,
    libssig_status checked
) {
	if (checked == LIBSSIG_ERROR_MEMORY || checked == LIBSSIG_ERROR_CRYPTO) {
		return checked;
	}

	if (checked == LIBSSIG_ERROR_REVOKED || current == LIBSSIG_ERROR_REVOKED) {
		return LIBSSIG_ERROR_REVOKED;
	}
	return checked != LIBSSIG_OK ? checked : current;
}

libssig_status libssig_verify_ocsp(
    const libssig_verify_params* params,
    libssig_verify_result*       result
) {
	for (size_t i = 0; i < result->count; ++i) {
		result->signers[i].ocsp = (libssig_ocsp_result){
		    .error = LIBSSIG_ERROR_NOT_FOUND,
		    .response_status = -1,
		    .reason = -1
		};
		result->signers[i].timestamp.ocsp = result->signers[i].ocsp;
	}
	libssig_status status = LIBSSIG_OK;
	for (size_t i = 0; i < params->ocsp_count; ++i) {
		const libssig_ocsp_evidence* item = &params->ocsp[i];
		if (item->signer_index >= result->count) {
			return LIBSSIG_ERROR_ARGUMENT;
		}
		status = status_merge(
		    status,
		    evidence_check(params, item, &result->signers[item->signer_index])
		);
		if (status == LIBSSIG_ERROR_MEMORY || status == LIBSSIG_ERROR_CRYPTO) {
			return status;
		}
	}
	for (size_t i = 0; i < result->count; ++i) {
		if (((params->options & LIBSSIG_VERIFY_REQUIRE_OCSP) &&
		     result->signers[i].ocsp.status != LIBSSIG_OCSP_GOOD) ||
		    ((params->options & LIBSSIG_VERIFY_REQUIRE_TSA_OCSP) &&
		     (!result->signers[i].timestamp.present ||
		      !result->signers[i].timestamp.valid ||
		      result->signers[i].timestamp.ocsp.status != LIBSSIG_OCSP_GOOD))) {
			status = status_merge(status, LIBSSIG_ERROR_OCSP);
		}
	}
	return status;
}

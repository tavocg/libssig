/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "internal.h"
#include <limits.h>

static bool params_valid(const libssig_ocsp_verify_params* params) {
	return params &&
	       libssig_ocsp_buffer_valid(
	           params->cert_data,
	           params->cert_data_len,
	           true
	       ) &&
	       libssig_ocsp_buffer_valid(
	           params->issuer_data,
	           params->issuer_data_len,
	           true
	       ) &&
	       libssig_ocsp_buffer_valid(
	           params->request,
	           params->request_len,
	           true
	       ) &&
	       libssig_ocsp_buffer_valid(
	           params->response,
	           params->response_len,
	           true
	       ) &&
	       libssig_ocsp_buffer_valid(
	           params->ca_data,
	           params->ca_data_len,
	           false
	       ) &&
	       libssig_ocsp_buffer_valid(
	           params->intermediates_data,
	           params->intermediates_data_len,
	           false
	       ) &&
	       params->max_age <= LONG_MAX && params->clock_skew <= LONG_MAX &&
	       !(params->options &
	         ~(LIBSSIG_OCSP_SYSTEM_TRUST | LIBSSIG_OCSP_ALLOW_MISSING_NONCE)) &&
	       (params->ca_data || (params->options & LIBSSIG_OCSP_SYSTEM_TRUST));
}

static bool extensions_valid(OCSP_REQUEST* request, OCSP_BASICRESP* basic) {
	int nonce = OCSP_REQUEST_get_ext_by_NID(
	    request,
	    NID_id_pkix_OCSP_Nonce,
	    -1
	);
	if (nonce < 0 ||
	    OCSP_REQUEST_get_ext_by_NID(request, NID_id_pkix_OCSP_Nonce, nonce) >=
	        0) {
		return false;
	}
	int response_nonce = OCSP_BASICRESP_get_ext_by_NID(
	    basic,
	    NID_id_pkix_OCSP_Nonce,
	    -1
	);
	if (response_nonce >= 0 && OCSP_BASICRESP_get_ext_by_NID(
	                               basic,
	                               NID_id_pkix_OCSP_Nonce,
	                               response_nonce
	                           ) >= 0) {
		return false;
	}
	for (int i = 0; i < OCSP_REQUEST_get_ext_count(request); ++i) {
		if (X509_EXTENSION_get_critical(OCSP_REQUEST_get_ext(request, i))) {
			return false;
		}
	}
	for (int i = 0; i < OCSP_BASICRESP_get_ext_count(basic); ++i) {
		if (X509_EXTENSION_get_critical(OCSP_BASICRESP_get_ext(basic, i))) {
			return false;
		}
	}
	return true;
}

static libssig_status response_check(
    const libssig_ocsp_verify_params* params,
    OCSP_REQUEST*                     request,
    OCSP_BASICRESP*                   basic,
    X509*                             cert,
    X509*                             issuer,
    libssig_ocsp_result*              result
) {
	if (OCSP_request_is_signed(request) ||
	    OCSP_request_onereq_count(request) != 1 ||
	    !extensions_valid(request, basic)) {
		return LIBSSIG_ERROR_VERIFY;
	}
	OCSP_ONEREQ* one = OCSP_request_onereq_get0(request, 0);
	for (int i = 0; i < OCSP_ONEREQ_get_ext_count(one); ++i) {
		if (X509_EXTENSION_get_critical(OCSP_ONEREQ_get_ext(one, i))) {
			return LIBSSIG_ERROR_UNSUPPORTED;
		}
	}

	OCSP_CERTID* expected = OCSP_cert_to_id(EVP_sha1(), cert, issuer);
	if (!expected) {
		return LIBSSIG_ERROR_CRYPTO;
	}
	OCSP_CERTID* requested = OCSP_onereq_get0_id(
	    OCSP_request_onereq_get0(request, 0)
	);
	libssig_status status = OCSP_id_cmp(expected, requested) == 0
	                            ? LIBSSIG_OK
	                            : LIBSSIG_ERROR_VERIFY;
	int            nonce = OCSP_check_nonce(request, basic);
	if (status == LIBSSIG_OK && nonce != 1 &&
	    !(nonce == -1 &&
	      (params->options & LIBSSIG_OCSP_ALLOW_MISSING_NONCE))) {
		status = LIBSSIG_ERROR_VERIFY;
	}

	if (status == LIBSSIG_OK) {
		status = libssig_ocsp_authenticate(params, issuer, basic);
	}

	if (status == LIBSSIG_OK) {
		status = libssig_ocsp_status_read(params, basic, expected, result);
	}
	OCSP_CERTID_free(expected);
	return status;
}

static libssig_status verify_run(
    const libssig_ocsp_verify_params* params,
    libssig_ocsp_result*              result
) {
	X509 *         cert = NULL, *issuer = NULL;
	libssig_status status = libssig_ocsp_certificate(
	    params->cert_data,
	    params->cert_data_len,
	    &cert
	);
	if (status == LIBSSIG_OK) {
		status = libssig_ocsp_certificate(
		    params->issuer_data,
		    params->issuer_data_len,
		    &issuer
		);
	}

	if (status == LIBSSIG_OK && !libssig_ocsp_issuer_valid(cert, issuer)) {
		status = LIBSSIG_ERROR_VERIFY;
	}
	const unsigned char* cursor = params->request;
	OCSP_REQUEST*        request = d2i_OCSP_REQUEST(
        NULL,
        &cursor,
        (long)params->request_len
    );
	if (status == LIBSSIG_OK &&
	    (!request || cursor != params->request + params->request_len)) {
		status = LIBSSIG_ERROR_FORMAT;
	}
	cursor = params->response;
	OCSP_RESPONSE* response = d2i_OCSP_RESPONSE(
	    NULL,
	    &cursor,
	    (long)params->response_len
	);
	OCSP_BASICRESP* basic = NULL;
	if (status == LIBSSIG_OK &&
	    (!response || cursor != params->response + params->response_len)) {
		status = LIBSSIG_ERROR_FORMAT;
	}

	if (status == LIBSSIG_OK) {
		result->response_status = OCSP_response_status(response);
		if (result->response_status != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
			status = LIBSSIG_ERROR_OCSP;
		} else {
			basic = OCSP_response_get1_basic(response);
			status = basic ? LIBSSIG_OK : LIBSSIG_ERROR_FORMAT;
		}
	}

	if (status == LIBSSIG_OK) {
		status = response_check(params, request, basic, cert, issuer, result);
	}
	OCSP_BASICRESP_free(basic);
	OCSP_RESPONSE_free(response);
	OCSP_REQUEST_free(request);
	X509_free(cert);
	X509_free(issuer);
	return status;
}

libssig_status libssig_ocsp_verify(
    const libssig_ocsp_verify_params* params,
    libssig_ocsp_result*              result
) {
	if (!result) {
		return LIBSSIG_ERROR_ARGUMENT;
	}
	*result = (libssig_ocsp_result){.response_status = -1, .reason = -1};
	libssig_status status = params_valid(params) ? verify_run(params, result)
	                                             : LIBSSIG_ERROR_ARGUMENT;
	if (status != LIBSSIG_OK) {
		int response_status = result->response_status;
		*result = (libssig_ocsp_result){.response_status = response_status,
		                                .reason = -1};
	}
	result->error = status;
	return status;
}

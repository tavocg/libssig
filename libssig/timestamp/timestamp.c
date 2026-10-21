/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "internal.h"
#include <libssig/document.h>
#include <limits.h>
#include <stdlib.h>

static bool buffer_valid(const unsigned char* data, size_t len, bool required) {
	return len <= INT_MAX && ((data && len) || (!required && !data && !len));
}

static bool params_valid(const libssig_timestamp_params* params) {
	return params && buffer_valid(params->data, params->data_len, true) &&
	       buffer_valid(params->request, params->request_len, true) &&
	       buffer_valid(params->response, params->response_len, true) &&
	       buffer_valid(
	           params->fallback_ca_data,
	           params->fallback_ca_data_len,
	           false
	       ) &&
	       buffer_valid(params->ca_data, params->ca_data_len, false) &&
	       buffer_valid(
	           params->intermediates_data,
	           params->intermediates_data_len,
	           false
	       ) &&
	       !(params->options & ~LIBSSIG_TIMESTAMP_SYSTEM_TRUST) &&
	       (params->ca_data ||
	        (params->options & LIBSSIG_TIMESTAMP_SYSTEM_TRUST));
}

static bool request_valid(TS_REQ* request, CMS_SignerInfo* signer) {
	const ASN1_INTEGER* nonce = TS_REQ_get_nonce(request);
	BIGNUM*             number = nonce ? ASN1_INTEGER_to_BN(nonce, NULL) : NULL;
	bool                ok = TS_REQ_get_version(request) == 1 &&
	          TS_REQ_get_cert_req(request) &&
	          TS_REQ_get_ext_count(request) == 0 && number &&
	          !BN_is_negative(number) && BN_num_bits(number) == 128 &&
	          libssig_timestamp_imprint(request, signer);
	BN_free(number);
	return ok;
}

static libssig_status timestamp_attach(
    CMS_ContentInfo*   cms,
    CMS_SignerInfo*    signer,
    TS_RESP*           response,
    libssig_signature* output
) {
	unsigned char* token = NULL;
	int            len = i2d_PKCS7(TS_RESP_get_token(response), &token);
	bool           ok = len > 0 && CMS_unsigned_add1_attr_by_NID(
                             signer,
                             NID_id_smime_aa_timeStampToken,
                             V_ASN1_SEQUENCE,
                             token,
                             len
                         );
	OPENSSL_free(token);
	if (!ok) {
		return LIBSSIG_ERROR_CRYPTO;
	}

	len = i2d_CMS_ContentInfo(cms, NULL);
	if (len <= 0) {
		return LIBSSIG_ERROR_CRYPTO;
	}

	output->data = malloc((size_t)len);
	if (!output->data) {
		return LIBSSIG_ERROR_MEMORY;
	}

	unsigned char* cursor = output->data;
	if (i2d_CMS_ContentInfo(cms, &cursor) != len) {
		libssig_signature_free(output);
		return LIBSSIG_ERROR_CRYPTO;
	}
	output->len = (size_t)len;
	return LIBSSIG_OK;
}

static libssig_status response_apply(
    const libssig_timestamp_params* params,
    CMS_ContentInfo*                cms,
    CMS_SignerInfo*                 signer,
    libssig_signature*              output
) {
	const unsigned char* cursor = params->request;
	TS_REQ* request = d2i_TS_REQ(NULL, &cursor, (long)params->request_len);
	bool    parsed = request && cursor == params->request + params->request_len;
	cursor = params->response;
	TS_RESP* response = d2i_TS_RESP(NULL, &cursor, (long)params->response_len);
	parsed = parsed && response &&
	         cursor == params->response + params->response_len;
	libssig_status status = LIBSSIG_ERROR_FORMAT;
	if (parsed) {
		status = request_valid(request, signer)
		             ? libssig_timestamp_response(params, request, response)
		             : LIBSSIG_ERROR_VERIFY;
	}

	if (status == LIBSSIG_OK) {
		status = timestamp_attach(cms, signer, response, output);
	}
	TS_REQ_free(request);
	TS_RESP_free(response);
	return status;
}

libssig_status libssig_timestamp(
    const libssig_timestamp_params* params,
    libssig_signature*              signature
) {
	if (!signature) {
		return LIBSSIG_ERROR_ARGUMENT;
	}

	*signature = (libssig_signature){0};
	if (!params_valid(params)) {
		return LIBSSIG_ERROR_ARGUMENT;
	}

	libssig_format format = libssig_document_format(
	    params->data,
	    params->data_len
	);
	if (format == LIBSSIG_FORMAT_JADES || format == LIBSSIG_FORMAT_XADES) {
		return libssig_document_timestamp(params, signature);
	}

	CMS_ContentInfo* cms = NULL;
	CMS_SignerInfo*  signer = NULL;
	libssig_status   status = libssig_timestamp_container(
        params->data,
        params->data_len,
        params->signer_index,
        &cms,
        &signer
    );
	if (status == LIBSSIG_OK) {
		status = response_apply(params, cms, signer, signature);
	}
	CMS_ContentInfo_free(cms);
	return status;
}

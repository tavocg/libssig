/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <libssig/pdf.h>
#include <libssig/services.h>
#include <libssig/validation.h>
#include <stdlib.h>
#include <string.h>

static libssig_status pdf_validation(
    const libssig_sign_params* params,
    CMS_ContentInfo*           cms,
    libssig_signature*         pdf
) {
	libssig_validation_data validation = {0};
	libssig_status          status = libssig_validation_collect(
        cms,
        params->services,
        &validation
    );
	libssig_pdf_revision revision = {0};
	libssig_signature    output = {0};
	if (status == LIBSSIG_OK) {
		status = libssig_pdf_open(pdf->data, pdf->len, &revision);
	}
	if (status == LIBSSIG_OK) {
		status = libssig_pdf_dss(&revision, &validation);
	}
	if (status == LIBSSIG_OK) {
		status = libssig_pdf_finish(&revision, &output);
	}
	if (status == LIBSSIG_OK) {
		libssig_signature_free(pdf);
		*pdf = output;
	}
	libssig_pdf_close(&revision);
	libssig_validation_free(&validation);
	return status;
}
libssig_status libssig_pdf_archive(
    const libssig_sign_params* params,
    libssig_signature*         pdf
) {
	libssig_pdf_revision revision = {0};
	libssig_signature    placeholder = {0}, content = {0}, query = {0},
	                  response = {0}, token = {0}, output = {0};
	libssig_status status = libssig_pdf_open(pdf->data, pdf->len, &revision);
	if (status == LIBSSIG_OK) {
		status = libssig_pdf_slot(&revision, true);
	}
	if (status == LIBSSIG_OK) {
		status = libssig_pdf_finish(&revision, &placeholder);
	}
	if (status == LIBSSIG_OK) {
		status = libssig_pdf_content(&revision, &content);
	}
	unsigned char hash[EVP_MAX_MD_SIZE];
	unsigned int  hash_len = 0;
	if (status == LIBSSIG_OK && !EVP_Digest(
	                                content.data,
	                                content.len,
	                                hash,
	                                &hash_len,
	                                libssig_timestamp_digest(params->hash),
	                                NULL
	                            )) {
		status = LIBSSIG_ERROR_CRYPTO;
	}
	if (status == LIBSSIG_OK) {
		status = libssig_ades_query(hash, hash_len, params->hash, &query);
	}
	if (status == LIBSSIG_OK) {
		status = libssig_ades_response(params->services, &query, &response);
	}
	const unsigned char* cursor = response.data;
	TS_RESP*             reply = status == LIBSSIG_OK
	                                 ? d2i_TS_RESP(NULL, &cursor, (long)response.len)
	                                 : NULL;
	if (status == LIBSSIG_OK) {
		unsigned char* bytes = NULL;
		int len = reply ? i2d_PKCS7(TS_RESP_get_token(reply), &bytes) : 0;
		if (len > 0) {
			token.data = malloc((size_t)len);
			if (token.data) {
				memcpy(token.data, bytes, (size_t)len);
				token.len = (size_t)len;
			}
		}
		OPENSSL_free(bytes);
		status = token.data ? libssig_pdf_insert(&revision, &token, &output)
		                    : LIBSSIG_ERROR_CRYPTO;
	}
	if (status == LIBSSIG_OK) {
		libssig_signature_free(pdf);
		*pdf = output;
	}
	TS_RESP_free(reply);
	libssig_signature_free(&placeholder);
	libssig_signature_free(&content);
	libssig_signature_free(&query);
	libssig_signature_free(&response);
	libssig_signature_free(&token);
	libssig_pdf_close(&revision);
	return status;
}
libssig_status libssig_pades_v121_finish(
    const libssig_sign_params* params,
    CMS_ContentInfo*           cms,
    libssig_signature*         output
) {
	libssig_status status = LIBSSIG_OK;
	if (params->level == LIBSSIG_LEVEL_B_LT ||
	    params->level == LIBSSIG_LEVEL_B_LTA) {
		status = pdf_validation(params, cms, output);
	}
	if (status == LIBSSIG_OK && params->level == LIBSSIG_LEVEL_B_LTA) {
		status = libssig_pdf_archive(params, output);
	}
	return status;
}

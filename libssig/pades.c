/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <libssig/internal.h>
#include <libssig/pades_internal.h>
#include <stdlib.h>

static bool signed_fields(
    qpdf_data pdf,
    qpdf_oh   fields,
    int       depth,
    bool      inherited
) {
	if (qpdf_oh_is_null(pdf, fields)) {
		return false;
	}
	if (depth > 16 || !qpdf_oh_is_array(pdf, fields) ||
	    qpdf_oh_get_array_n_items(pdf, fields) > 1024) {
		return true;
	}
	for (int i = 0; i < qpdf_oh_get_array_n_items(pdf, fields); ++i) {
		qpdf_oh field = qpdf_oh_get_array_item(pdf, fields, i);
		qpdf_oh type = qpdf_oh_get_key_if_dict(pdf, field, "/FT");
		bool    signature = qpdf_oh_is_null(pdf, type)
		                        ? inherited
		                        : qpdf_oh_is_name_and_equals(pdf, type, "/Sig");
		if (signature &&
		    !qpdf_oh_is_null(pdf, qpdf_oh_get_key_if_dict(pdf, field, "/V"))) {
			return true;
		}
		if (signed_fields(
		        pdf,
		        qpdf_oh_get_key_if_dict(pdf, field, "/Kids"),
		        depth + 1,
		        signature
		    )) {
			return true;
		}
	}
	return false;
}

static libssig_status pdf_signature(
    const libssig_context*     ctx,
    const libssig_sign_params* params,
    libssig_signature*         pdf,
    CMS_ContentInfo**          out_cms
) {
	libssig_pdf_revision revision = {0};
	libssig_signature    placeholder = {0}, content = {0}, signature = {0};
	libssig_status       status = libssig_pdf_open(
        params->data,
        params->data_len,
        &revision
    );
	if (status == LIBSSIG_OK) {
		qpdf_oh form = qpdf_oh_get_key(
		    revision.pdf,
		    revision.root,
		    "/AcroForm"
		);
		if (signed_fields(
		        revision.pdf,
		        qpdf_oh_get_key_if_dict(revision.pdf, form, "/Fields"),
		        0,
		        false
		    )) {
			status = LIBSSIG_ERROR_UNSUPPORTED;
		}
	}
	if (status == LIBSSIG_OK) {
		status = libssig_pdf_slot(&revision, false);
	}
	if (status == LIBSSIG_OK) {
		status = libssig_pdf_finish(&revision, &placeholder);
	}
	if (status == LIBSSIG_OK) {
		status = libssig_pdf_content(&revision, &content);
	}
	libssig_key_sign_params signing = {
	    .token = params->token,
	    .id = params->cert->id,
	    .id_len = params->cert->id_len,
	    .pin = params->pin,
	    .pin_len = params->pin_len,
	    .data = content.data,
	    .data_len = content.len,
	    .algo = params->algo,
	    .hash = params->hash,
	    .pades = true,
	    .mime_type = "application/pdf",
	    .options = LIBSSIG_SIGN_DETACHED,
	};
	if (status == LIBSSIG_OK) {
		status = libssig_cades_sign(ctx, &signing, params->cert, &signature);
	}
	if (status == LIBSSIG_OK) {
		const unsigned char* cursor = signature.data;
		*out_cms = d2i_CMS_ContentInfo(NULL, &cursor, (long)signature.len);
		if (!*out_cms) {
			status = LIBSSIG_ERROR_CRYPTO;
		}
	}
	if (status == LIBSSIG_OK && params->level != LIBSSIG_LEVEL_B_B) {
		libssig_extend_params extend = {
		    .hash = params->hash,
		    .services = params->services
		};
		status = libssig_ades_stamps(*out_cms, &extend);
		libssig_signature_free(&signature);
		if (status == LIBSSIG_OK) {
			status = libssig_ades_encode(*out_cms, &signature);
		}
	}
	if (status == LIBSSIG_OK) {
		status = libssig_pdf_insert(&revision, &signature, pdf);
	}
	if (status != LIBSSIG_OK) {
		pdf->ck_rv = signature.ck_rv;
	}
	libssig_signature_free(&placeholder);
	libssig_signature_free(&content);
	libssig_signature_free(&signature);
	libssig_pdf_close(&revision);
	return status;
}
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
static libssig_status pdf_archive(
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
libssig_status libssig_pades_finish(
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
		status = pdf_archive(params, output);
	}
	return status;
}
libssig_status libssig_pades_sign(
    const libssig_context*     ctx,
    const libssig_sign_params* params,
    libssig_signature*         output
) {
	if (params->options & LIBSSIG_SIGN_DETACHED) {
		return LIBSSIG_ERROR_ARGUMENT;
	}
	CMS_ContentInfo* cms = NULL;
	libssig_status   status = pdf_signature(ctx, params, output, &cms);
	if (status == LIBSSIG_OK) {
		status = libssig_pades_finish(params, cms, output);
	}
	CMS_ContentInfo_free(cms);
	if (status != LIBSSIG_OK) {
		unsigned long rv = output->ck_rv;
		libssig_signature_free(output);
		output->ck_rv = rv;
	}
	return status;
}

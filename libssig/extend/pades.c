/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "internal.h"
#include <libssig/pdf.h>
#include <stdlib.h>
#include <string.h>

/* Once later signatures cover a CMS hole, renewal must append revisions;
 * rewriting that hole would invalidate those signatures. */
static libssig_status pades_renew(
    const libssig_extend_params* params,
    libssig_signature*           output
) {
	const libssig_verify_params defaults = {
	    .options = LIBSSIG_VERIFY_SYSTEM_TRUST | LIBSSIG_VERIFY_TSA_SYSTEM_TRUST
	};
	libssig_verify_params verify = params->services && params->services->trust
	                                   ? *params->services->trust
	                                   : defaults;
	verify.data = params->data;
	verify.data_len = params->data_len;
	libssig_verify_result result = {0};
	libssig_status        status = libssig_verify(&verify, &result);
	bool                  needs_time = false, has_archive = false;
	for (size_t i = 0; i < result.count; ++i) {
		needs_time |= !result.signers[i].timestamp.present;
		has_archive |= result.signers[i].archive.present;
	}
	libssig_verify_free(&result);
	libssig_signature staged = {0};
	if (status == LIBSSIG_OK) {
		staged.data = malloc(params->data_len);
		if (!staged.data) {
			status = LIBSSIG_ERROR_MEMORY;
		} else {
			memcpy(staged.data, params->data, params->data_len);
			staged.len = params->data_len;
		}
	}
	libssig_sign_params signing = {
	    .level = params->level,
	    .hash = params->hash,
	    .services = params->services
	};
	if (status == LIBSSIG_OK && needs_time &&
	    params->level != LIBSSIG_LEVEL_B_B) {
		/* This document timestamp is the B-T existence proof for every
		 * approval. Collect its TSA evidence before the final archive. */
		status = libssig_pdf_archive(&signing, &staged);
	}
	if (params->level == LIBSSIG_LEVEL_B_B ||
	    params->level == LIBSSIG_LEVEL_B_T) {
		if (status == LIBSSIG_OK) {
			*output = staged;
		} else {
			libssig_signature_free(&staged);
		}
		return status;
	}
	qpdf_data pdf = qpdf_init();
	if (!pdf && status == LIBSSIG_OK) {
		status = LIBSSIG_ERROR_MEMORY;
	}
	if (pdf) {
		qpdf_silence_errors(pdf);
		qpdf_set_suppress_warnings(pdf, QPDF_TRUE);
		qpdf_set_attempt_recovery(pdf, QPDF_FALSE);
		if (status == LIBSSIG_OK && qpdf_read_memory(
		                                pdf,
		                                "PDF renewal",
		                                (const char*)staged.data,
		                                staged.len,
		                                NULL
		                            ) != QPDF_SUCCESS) {
			status = LIBSSIG_ERROR_FORMAT;
		}
	}
	qpdf_oh fields = 0;
	if (status == LIBSSIG_OK) {
		status = libssig_pdf_fields(pdf, &fields);
	}
	verify.data = staged.data;
	verify.data_len = staged.len;
	libssig_validation_data evidence = {0};
	size_t                  previous_end = 0;
	int count = status == LIBSSIG_OK ? qpdf_oh_get_array_n_items(pdf, fields)
	                                 : 0;
	for (int i = 0; status == LIBSSIG_OK && i < count; ++i) {
		qpdf_oh               field = qpdf_oh_get_array_item(pdf, fields, i);
		libssig_pdf_signature signature = {0};
		status = libssig_pdf_signature_read(
		    pdf,
		    qpdf_oh_get_key_if_dict(pdf, field, "/V"),
		    &verify,
		    &signature
		);
		if (status == LIBSSIG_OK && signature.end <= previous_end) {
			status = LIBSSIG_ERROR_EVIDENCE;
		}
		previous_end = signature.end;
		if (status == LIBSSIG_OK && !signature.timestamp) {
			const unsigned char* cursor = signature.cms.data;
			CMS_ContentInfo*     cms = d2i_CMS_ContentInfo(
                NULL,
                &cursor,
                (long)signature.cms.len
            );
			status = cms ? libssig_validation_collect(
			                   cms,
			                   params->services,
			                   &evidence
			               )
			             : LIBSSIG_ERROR_FORMAT;
			CMS_ContentInfo_free(cms);
		} else if (status == LIBSSIG_OK) {
			status = libssig_validation_timestamp_collect(
			    &signature.cms,
			    params->services,
			    &evidence
			);
		}
		libssig_signature_free(&signature.cms);
		libssig_signature_free(&signature.content);
	}
	libssig_pdf_revision revision = {0};
	if (status == LIBSSIG_OK) {
		status = libssig_pdf_open(staged.data, staged.len, &revision);
	}
	if (status == LIBSSIG_OK) {
		status = libssig_pdf_dss(&revision, &evidence);
	}
	if (status == LIBSSIG_OK) {
		status = libssig_pdf_finish(&revision, output);
	}
	libssig_pdf_close(&revision);
	libssig_validation_free(&evidence);
	libssig_signature_free(&staged);
	if (pdf) {
		qpdf_cleanup(&pdf);
	}
	if (status == LIBSSIG_OK &&
	    (params->level == LIBSSIG_LEVEL_B_LTA || has_archive)) {
		status = libssig_pdf_archive(&signing, output);
	}
	if (status != LIBSSIG_OK) {
		libssig_signature_free(output);
	}
	return status;
}

libssig_status libssig_pades_v121_extend(
    const libssig_extend_params* params,
    libssig_signature*           output
) {
	if (params->content || params->content_len) {
		return LIBSSIG_ERROR_ARGUMENT;
	}
	qpdf_data pdf = qpdf_init();
	if (!pdf) {
		return LIBSSIG_ERROR_MEMORY;
	}
	qpdf_silence_errors(pdf);
	qpdf_set_suppress_warnings(pdf, QPDF_TRUE);
	qpdf_set_attempt_recovery(pdf, QPDF_FALSE);
	libssig_status status = qpdf_read_memory(
	                            pdf,
	                            "libssig augmentation",
	                            (const char*)params->data,
	                            params->data_len,
	                            NULL
	                        ) == QPDF_SUCCESS
	                            ? LIBSSIG_OK
	                            : LIBSSIG_ERROR_FORMAT;
	qpdf_oh        fields = 0;
	if (status == LIBSSIG_OK) {
		status = libssig_pdf_fields(pdf, &fields);
	}
	qpdf_oh value = 0;
	int     count = 0;
	if (status == LIBSSIG_OK && qpdf_oh_is_array(pdf, fields)) {
		for (int i = 0; i < qpdf_oh_get_array_n_items(pdf, fields); ++i) {
			qpdf_oh field = qpdf_oh_get_array_item(pdf, fields, i);
			qpdf_oh type = qpdf_oh_get_key_if_dict(pdf, field, "/FT");
			qpdf_oh candidate = qpdf_oh_get_key_if_dict(pdf, field, "/V");
			if (qpdf_oh_is_name_and_equals(pdf, type, "/Sig") &&
			    !qpdf_oh_is_null(pdf, candidate)) {
				value = candidate;
				++count;
			}
		}
	}
	if (status == LIBSSIG_OK && count > 1 && count <= 1024) {
		status = pades_renew(params, output);
		qpdf_cleanup(&pdf);
		return status;
	}
	if (status == LIBSSIG_OK && count != 1) {
		status = LIBSSIG_ERROR_UNSUPPORTED;
	}
	libssig_pdf_signature signature = {0};
	libssig_verify_params source = {
	    .options = LIBSSIG_VERIFY_CURRENT_TIME,
	    .data = params->data,
	    .data_len = params->data_len
	};
	if (status == LIBSSIG_OK) {
		status = libssig_pdf_signature_read(pdf, value, &source, &signature);
	}
	if (status == LIBSSIG_OK &&
	    (signature.timestamp || signature.end != params->data_len)) {
		status = LIBSSIG_ERROR_UNSUPPORTED;
	}
	libssig_verify_result result = {0};
	if (status == LIBSSIG_OK) {
		status = libssig_verify(&source, &result);
	}
	libssig_verify_free(&result);
	const unsigned char* cursor = signature.cms.data;
	CMS_ContentInfo*     cms = status == LIBSSIG_OK ? d2i_CMS_ContentInfo(
                                                      NULL,
                                                      &cursor,
                                                      (long)signature.cms.len
                                                  )
	                                                : NULL;
	if (status == LIBSSIG_OK && !cms) {
		status = LIBSSIG_ERROR_FORMAT;
	}
	if (status == LIBSSIG_OK && params->level != LIBSSIG_LEVEL_B_B) {
		status = libssig_ades_stamps(cms, params);
	}
	libssig_signature encoded = {0};
	if (status == LIBSSIG_OK) {
		status = libssig_cms_encode(cms, &encoded);
	}
	if (status == LIBSSIG_OK &&
	    encoded.len > (signature.hole_end - signature.hole_start - 2) / 2) {
		status = LIBSSIG_ERROR_MEMORY;
	}
	if (status == LIBSSIG_OK) {
		output->data = malloc(params->data_len);
		if (!output->data) {
			status = LIBSSIG_ERROR_MEMORY;
		} else {
			memcpy(output->data, params->data, params->data_len);
			output->len = params->data_len;
			memset(
			    output->data + signature.hole_start + 1,
			    '0',
			    signature.hole_end - signature.hole_start - 2
			);
			const char* hex = "0123456789ABCDEF";
			for (size_t i = 0; i < encoded.len; ++i) {
				output->data[signature.hole_start + 1 + i * 2] = hex
				    [encoded.data[i] >> 4];
				output->data[signature.hole_start + 2 + i * 2] = hex
				    [encoded.data[i] & 15];
			}
		}
	}
	libssig_sign_params finish = {
	    .level = params->level,
	    .hash = params->hash,
	    .services = params->services
	};
	if (status == LIBSSIG_OK) {
		status = libssig_pades_v121_finish(&finish, cms, output);
	}
	libssig_signature_free(&encoded);
	CMS_ContentInfo_free(cms);
	libssig_signature_free(&signature.cms);
	libssig_signature_free(&signature.content);
	qpdf_cleanup(&pdf);
	if (status != LIBSSIG_OK) {
		libssig_signature_free(output);
	}
	return status;
}

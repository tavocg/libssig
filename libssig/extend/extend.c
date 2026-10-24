/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "internal.h"
#include <libssig/document.h>
#include <libssig/multisign.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

libssig_status libssig_extend(
    const libssig_extend_params* params,
    libssig_signature*           output
) {
	if (!output) {
		return LIBSSIG_ERROR_ARGUMENT;
	}
	*output = (libssig_signature){0};
	if (!params || !params->data || !params->data_len ||
	    params->data_len > INT_MAX || params->content_len > INT_MAX ||
	    (!params->content && params->content_len) ||
	    !libssig_level_valid(params->level) ||
	    !libssig_timestamp_digest(params->hash) ||
	    (params->services && (params->services->ocsp_options &
	                          ~LIBSSIG_OCSP_ALLOW_MISSING_NONCE)) ||
	    (params->level != LIBSSIG_LEVEL_B_B &&
	     (!params->services || !params->services->exchange ||
	      !params->services->tsa_url))) {
		return LIBSSIG_ERROR_ARGUMENT;
	}
	libssig_multisign document = {0};
	libssig_status    parsed = libssig_multisign_read(
        params->data,
        params->data_len,
        &document
    );
	if (parsed == LIBSSIG_OK && document.collection) {
		libssig_status status = LIBSSIG_OK;
		for (size_t i = 0; status == LIBSSIG_OK && i < document.count; ++i) {
			if (document.format == LIBSSIG_FORMAT_CADES ||
			    document.format == LIBSSIG_FORMAT_CMS) {
				libssig_multisign_protected_view(&document.parts[i]);
			}
			libssig_extend_params single = *params;
			single.data = document.parts[i].data;
			single.data_len = document.parts[i].len;
			libssig_signature extended = {0};
			status = libssig_extend(&single, &extended);
			if (status == LIBSSIG_OK) {
				libssig_signature_free(&document.parts[i]);
				document.parts[i] = extended;
			} else {
				libssig_signature_free(&extended);
			}
		}
		if (status == LIBSSIG_OK) {
			status = libssig_multisign_merge(&document, output);
		}
		libssig_multisign_free(&document);
		if (status != LIBSSIG_OK) {
			libssig_signature_free(output);
		}
		return status;
	}
	libssig_multisign_free(&document);
	if (parsed != LIBSSIG_OK && parsed != LIBSSIG_ERROR_NOT_FOUND) {
		return parsed;
	}
	libssig_format format = libssig_document_format(
	    params->data,
	    params->data_len
	);
	if (format == LIBSSIG_FORMAT_JADES) {
		return libssig_jades_v121_extend(params, output);
	}
	if (format == LIBSSIG_FORMAT_XADES) {
		return libssig_xades_v131_extend(params, output);
	}
	if (params->data_len >= 5 && !memcmp(params->data, "%PDF-", 5)) {
		return libssig_pades_v121_extend(params, output);
	}
	return libssig_cades_v131_extend(params, output);
}

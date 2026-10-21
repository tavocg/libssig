/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <libssig/jades.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

libssig_status libssig_jades_sign(
    const libssig_context*     ctx,
    const libssig_sign_params* params,
    libssig_signature*         output
) {
	const unsigned char* cursor = params->cert->der;
	X509*          cert = d2i_X509(NULL, &cursor, (long)params->cert->der_len);
	libssig_algo   algo;
	libssig_hash   hash;
	const char*    name = libssig_jades_alg_name(params->algo, params->hash);
	libssig_status status = cert && cursor == params->cert->der +
	                                              params->cert->der_len
	                            ? libssig_jades_alg(name, cert, &algo, &hash)
	                            : LIBSSIG_ERROR_FORMAT;
	X509_free(cert);
	if (status != LIBSSIG_OK) {
		return status;
	}
	char* cert_text = libssig_base64(
	    params->cert->der,
	    params->cert->der_len,
	    false
	);
	char*   payload = libssig_base64(params->data, params->data_len, true);
	json_t* header = cert_text ? json_pack(
	                                 "{s:s,s:i,s:[s]}",
	                                 "alg",
	                                 name,
	                                 "iat",
	                                 (int)time(NULL),
	                                 "x5c",
	                                 cert_text
	                             )
	                           : NULL;
	if (header) {
		json_object_set_new(
		    header,
		    "iat",
		    json_integer((json_int_t)time(NULL))
		);
	}
	if (header && params->mime_type) {
		json_object_set_new(header, "cty", json_string(params->mime_type));
	}
	libssig_signature encoded = {0};
	bool              ok = payload && libssig_jades_write(header, &encoded);
	char* protected_text = ok ? libssig_base64(encoded.data, encoded.len, true)
	                          : NULL;
	libssig_signature_free(&encoded);
	json_decref(header);
	free(cert_text);
	libssig_jades doc = {
	    .root = protected_text ? json_pack("{s:s}", "protected", protected_text)
	                           : NULL,
	    .payload = payload
	};
	free(protected_text);
	if (!doc.root) {
		status = LIBSSIG_ERROR_MEMORY;
	}
	if (status == LIBSSIG_OK && !(params->options & LIBSSIG_SIGN_DETACHED) &&
	    json_object_set_new(doc.root, "payload", json_string(payload))) {
		status = LIBSSIG_ERROR_MEMORY;
	}
	if (status == LIBSSIG_OK && !libssig_jades_input(&doc, &encoded)) {
		status = LIBSSIG_ERROR_MEMORY;
	}
	libssig_signature raw = {0};
	if (status == LIBSSIG_OK) {
		status = libssig_document_sign(ctx, params, &encoded, &raw);
	}
	char* sig = status == LIBSSIG_OK ? libssig_base64(raw.data, raw.len, true)
	                                 : NULL;
	if (status == LIBSSIG_OK &&
	    (!sig ||
	     json_object_set_new(doc.root, "signature", json_string(sig)))) {
		status = LIBSSIG_ERROR_MEMORY;
	}
	free(sig);
	libssig_signature_free(&encoded);
	if (status != LIBSSIG_OK) {
		output->ck_rv = raw.ck_rv;
	}
	libssig_signature_free(&raw);
	libssig_signature baseline = {0};
	if (status == LIBSSIG_OK && !libssig_jades_write(doc.root, &baseline)) {
		status = LIBSSIG_ERROR_MEMORY;
	}
	if (status == LIBSSIG_OK && params->level != LIBSSIG_LEVEL_B_B) {
		static const unsigned char empty = 0;
		libssig_extend_params      extend = {
		         .data = baseline.data,
		         .data_len = baseline.len,
		         .content = params->options & LIBSSIG_SIGN_DETACHED
		                        ? (params->data ? params->data : &empty)
		                        : NULL,
		         .content_len = params->options & LIBSSIG_SIGN_DETACHED
		                            ? params->data_len
		                            : 0,
		         .level = params->level,
		         .hash = params->hash,
		         .services = params->services
        };
		status = libssig_jades_extend(&extend, output);
	} else if (status == LIBSSIG_OK) {
		*output = baseline;
		baseline = (libssig_signature){0};
	}
	libssig_signature_free(&baseline);
	libssig_jades_free(&doc);
	return status;
}

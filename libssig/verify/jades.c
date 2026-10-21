/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "internal.h"
#include <libssig/jades.h>
#include <stdlib.h>
#include <string.h>

static libssig_status token_certs_add(
    libssig_jades*           doc,
    const libssig_signature* token
) {
	const unsigned char* cursor = token->data;
	CMS_ContentInfo* cms = d2i_CMS_ContentInfo(NULL, &cursor, (long)token->len);
	STACK_OF(X509)* certs = cms ? CMS_get1_certs(cms) : NULL;
	libssig_status status = cms ? libssig_verify_certs_append(
	                                  doc->evidence.certs,
	                                  certs
	                              )
	                            : LIBSSIG_ERROR_FORMAT;
	sk_X509_pop_free(certs, X509_free);
	CMS_ContentInfo_free(cms);
	return status;
}
static libssig_status unsigned_read(
    libssig_jades*               doc,
    const libssig_verify_params* params,
    libssig_verify_result*       result
) {
	libssig_verify_signer* signer = &result->signers[0];
	size_t                 count = json_array_size(doc->unsigned_items);
	bool                   has_archive = false;
	for (size_t i = 0; i < count; ++i) {
		json_t* item = libssig_jades_item(
		    json_array_get(doc->unsigned_items, i)
		);
		if (json_object_get(item, "arcTst")) {
			has_archive = true;
		}
		json_decref(item);
	}
	libssig_verify_params selected = *params;
	if (has_archive && !(params->options & LIBSSIG_VERIFY_CURRENT_TIME)) {
		selected.options |= LIBSSIG_VERIFY_HISTORICAL;
	}
	bool validation = false;
	bool timestamp_seen = false;
	for (size_t i = 0; i < count; ++i) {
		json_t* item = libssig_jades_item(
		    json_array_get(doc->unsigned_items, i)
		);
		if (!json_is_object(item) || json_object_size(item) != 1) {
			json_decref(item);
			return LIBSSIG_ERROR_FORMAT;
		}
		const char*    key = json_object_iter_key(json_object_iter(item));
		json_t*        value = json_object_get(item, key);
		libssig_status status = LIBSSIG_OK;
		if (!strcmp(key, "anyValData")) {
			status = libssig_jades_evidence_read(doc, value);
			validation = true;
		} else if (!strcmp(key, "sigTst") || !strcmp(key, "arcTst")) {
			bool              archive = !strcmp(key, "arcTst");
			libssig_signature token = {0}, input = {0};
			if ((!archive && timestamp_seen) || (archive && !timestamp_seen) ||
			    !libssig_jades_timestamp_read(value, &token)) {
				status = LIBSSIG_ERROR_FORMAT;
			}
			if (status == LIBSSIG_OK) {
				const char* signature = json_string_value(
				    json_object_get(doc->root, "signature")
				);
				bool ok = archive ? libssig_jades_archive_input(doc, i, &input)
				                  : libssig_bytes_append(
				                        &input,
				                        signature,
				                        strlen(signature)
				                    );
				if (!ok) {
					status = LIBSSIG_ERROR_MEMORY;
				}
			}
			libssig_verify_timestamp checked = {0};
			libssig_verify_params    trust = selected;
			if (archive && i + 1 == count) {
				trust.options &= ~LIBSSIG_VERIFY_HISTORICAL;
			}
			if (status == LIBSSIG_OK) {
				status = libssig_document_stamp_verify(
				    &input,
				    &token,
				    &trust,
				    &checked
				);
			}
			if (status == LIBSSIG_OK && !archive) {
				status = token_certs_add(doc, &token);
			}
			if (status == LIBSSIG_OK) {
				libssig_verify_timestamp* target = archive ? &signer->archive
				                                           : &signer->timestamp;
				free(target->cert_der);
				*target = checked;
				checked.cert_der = NULL;
				if (archive) {
					signer->level = LIBSSIG_LEVEL_B_LTA;
					if (i + 1 != count) {
						has_archive = false;
					} else {
						has_archive = true;
					}
				} else {
					timestamp_seen = true;
					signer->level = LIBSSIG_LEVEL_B_T;
				}
			}
			if (status != LIBSSIG_OK) {
				libssig_verify_timestamp* target = archive ? &signer->archive
				                                           : &signer->timestamp;
				free(target->cert_der);
				*target = checked;
				target->present = true;
				target->status = status;
				checked.cert_der = NULL;
			}
			free(checked.cert_der);
			libssig_signature_free(&token);
			libssig_signature_free(&input);
		} else {
			status = LIBSSIG_ERROR_UNSUPPORTED;
		}
		json_decref(item);
		if (status != LIBSSIG_OK) {
			return status;
		}
	}
	if (signer->archive.present && !has_archive) {
		return LIBSSIG_ERROR_EVIDENCE;
	}
	if (validation && !signer->archive.present && timestamp_seen) {
		signer->level = LIBSSIG_LEVEL_B_LT;
	}
	return LIBSSIG_OK;
}
static libssig_status archives_history_check(
    libssig_jades*               doc,
    const libssig_verify_params* params,
    const libssig_verify_result* result
) {
	const libssig_verify_signer* signer = &result->signers[0];
	if (signer->level != LIBSSIG_LEVEL_B_LTA ||
	    (params->options & LIBSSIG_VERIFY_CURRENT_TIME)) {
		return LIBSSIG_OK;
	}
	for (size_t i = 0; i + 1 < json_array_size(doc->unsigned_items); ++i) {
		json_t* item = libssig_jades_item(
		    json_array_get(doc->unsigned_items, i)
		);
		json_t*        value = json_object_get(item, "arcTst");
		libssig_status status = LIBSSIG_OK;
		if (value) {
			libssig_signature        token = {0}, input = {0};
			libssig_verify_timestamp stamp = {0};
			libssig_verify_params    selected = *params;
			selected.options |= LIBSSIG_VERIFY_HISTORICAL;
			status = libssig_jades_timestamp_read(value, &token) &&
			                 libssig_jades_archive_input(doc, i, &input)
			             ? libssig_document_stamp_verify(
			                   &input,
			                   &token,
			                   &selected,
			                   &stamp
			               )
			             : LIBSSIG_ERROR_TIMESTAMP;
			if (status == LIBSSIG_OK) {
				status = libssig_document_evidence_stamp_check(
				    &stamp,
				    &signer->archive,
				    &doc->evidence,
				    params
				);
			}
			free(stamp.cert_der);
			libssig_signature_free(&token);
			libssig_signature_free(&input);
		}
		json_decref(item);
		if (status != LIBSSIG_OK) {
			return status;
		}
	}
	return LIBSSIG_OK;
}

libssig_status libssig_jades_verify(
    const libssig_verify_params* params,
    libssig_verify_result*       result
) {
	libssig_jades  doc = {0};
	libssig_status status = libssig_jades_read(params, &doc);
	libssig_algo   algo;
	libssig_hash   hash;
	if (status == LIBSSIG_OK) {
		status = libssig_jades_alg(
		    json_string_value(json_object_get(doc.protected, "alg")),
		    doc.cert,
		    &algo,
		    &hash
		);
	}
	libssig_signature input = {0};
	if (status == LIBSSIG_OK && !libssig_jades_input(&doc, &input)) {
		status = LIBSSIG_ERROR_MEMORY;
	}
	if (status == LIBSSIG_OK && !libssig_document_signature_check(
	                                doc.cert,
	                                algo,
	                                hash,
	                                input.data,
	                                input.len,
	                                &doc.signature
	                            )) {
		status = LIBSSIG_ERROR_VERIFY;
	}
	if (status == LIBSSIG_OK) {
		result->signers = calloc(1, sizeof(*result->signers));
		if (!result->signers) {
			status = LIBSSIG_ERROR_MEMORY;
		}
	}
	if (status == LIBSSIG_OK) {
		result->count = 1;
		result->format = LIBSSIG_FORMAT_JADES;
		result->signature_valid = true;
		result->detached = !json_object_get(doc.root, "payload");
		libssig_verify_signer* signer = &result->signers[0];
		signer->level = LIBSSIG_LEVEL_B_B;
		signer->level_detected = true;
		unsigned char* der = NULL;
		int            len = i2d_X509(doc.cert, &der);
		if (len <= 0 || !libssig_bytes_append(&input, NULL, 0)) {
			status = LIBSSIG_ERROR_CRYPTO;
		} else {
			signer->cert_der = malloc((size_t)len);
			if (!signer->cert_der) {
				status = LIBSSIG_ERROR_MEMORY;
			} else {
				memcpy(signer->cert_der, der, (size_t)len);
				signer->cert_der_len = (size_t)len;
			}
		}
		OPENSSL_free(der);
	}
	if (status == LIBSSIG_OK) {
		status = unsigned_read(&doc, params, result);
	}
	if (status == LIBSSIG_OK) {
		status = libssig_document_validate(
		    doc.cert,
		    &doc.evidence,
		    params,
		    result
		);
	}
	if (status == LIBSSIG_OK) {
		status = archives_history_check(&doc, params, result);
	}
	libssig_verify_profiles_finish(status, result);
	libssig_signature_free(&input);
	libssig_jades_free(&doc);
	return status;
}

/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <libssig/jades.h>
#include <stdlib.h>
#include <string.h>

static bool evidence_add(
    libssig_jades*                 doc,
    const libssig_validation_data* evidence
) {
	json_t* certs = json_array();
	json_t* revocations = json_object();
	bool    ok = certs && revocations;
	for (int i = 0; ok && i < sk_X509_num(evidence->certs); ++i) {
		unsigned char* der = NULL;
		X509*          cert = sk_X509_value(evidence->certs, i);
		if (X509_cmp(cert, doc->cert) == 0) {
			continue;
		}
		int               len = i2d_X509(cert, &der);
		libssig_signature bytes = {
		    .data = der,
		    .len = len > 0 ? (size_t)len : 0
		};
		json_t* pki = len > 0 ? libssig_jades_pki(&bytes) : NULL;
		json_t* item = pki ? json_pack("{s:o}", "x509Cert", pki) : NULL;
		ok = item && json_array_append(certs, item) == 0;
		json_decref(item);
		OPENSSL_free(der);
	}
	for (int i = 0; ok && i < sk_ASN1_TYPE_num(evidence->revocations); ++i) {
		libssig_signature bytes = {0};
		bool              ocsp = false;
		ok = libssig_validation_revocation_read(
		    sk_ASN1_TYPE_value(evidence->revocations, i),
		    &bytes,
		    &ocsp
		);
		const char* kind = ocsp ? "ocspVals" : "crlVals";
		json_t*     items = json_object_get(revocations, kind);
		if (!items) {
			items = json_array();
			ok = ok && items &&
			     json_object_set_new(revocations, kind, items) == 0;
		}
		json_t* pki = ok ? libssig_jades_pki(&bytes) : NULL;
		ok = pki && json_array_append(items, pki) == 0;
		json_decref(pki);
		libssig_signature_free(&bytes);
	}
	json_t* data = json_object();
	if (ok && json_array_size(certs)) {
		ok = json_object_set(data, "xVals", certs) == 0;
	}
	if (ok && json_object_size(revocations)) {
		ok = json_object_set(data, "rVals", revocations) == 0;
	}
	json_t* item = ok ? json_pack("{s:O}", "anyValData", data) : NULL;
	ok = item && libssig_jades_add(doc, item);
	json_decref(data);
	json_decref(certs);
	json_decref(revocations);
	return ok;
}
libssig_status libssig_jades_extend(
    const libssig_extend_params* params,
    libssig_signature*           output
) {
	libssig_verify_params verify = {
	    .data = params->data,
	    .data_len = params->data_len,
	    .content = params->content,
	    .content_len = params->content_len,
	    .options = LIBSSIG_VERIFY_CURRENT_TIME
	};
	libssig_verify_result result = {0};
	libssig_status        status = libssig_jades_verify(&verify, &result);
	libssig_level         current = result.count ? result.signers[0].level
	                                             : LIBSSIG_LEVEL_B_B;
	libssig_verify_free(&result);
	if (status != LIBSSIG_OK) {
		return status;
	}
	libssig_jades doc = {0};
	status = libssig_jades_read(&verify, &doc);
	if (status == LIBSSIG_OK && !doc.unsigned_items &&
	    params->level != LIBSSIG_LEVEL_B_B) {
		json_t* items = json_array();
		json_t* header = items ? json_pack("{s:o}", "etsiU", items) : NULL;
		if (!header || json_object_set_new(doc.root, "header", header)) {
			status = LIBSSIG_ERROR_MEMORY;
		}
		doc.unsigned_items = json_object_get(
		    json_object_get(doc.root, "header"),
		    "etsiU"
		);
	}
	libssig_signature stamp = {0}, input = {0};
	if (status == LIBSSIG_OK && params->level != LIBSSIG_LEVEL_B_B &&
	    current == LIBSSIG_LEVEL_B_B) {
		const char* sig = json_string_value(
		    json_object_get(doc.root, "signature")
		);
		if (!libssig_bytes_append(&input, sig, strlen(sig))) {
			status = LIBSSIG_ERROR_MEMORY;
		}
		if (status == LIBSSIG_OK) {
			status = libssig_document_stamp(
			    &input,
			    params->hash,
			    params->services,
			    &stamp
			);
		}
		if (status == LIBSSIG_OK &&
		    !libssig_jades_timestamp_add(&doc, "sigTst", &stamp)) {
			status = LIBSSIG_ERROR_MEMORY;
		}
		libssig_signature_free(&input);
	}
	if (status == LIBSSIG_OK && (params->level == LIBSSIG_LEVEL_B_LT ||
	                             params->level == LIBSSIG_LEVEL_B_LTA)) {
		if (!stamp.data) {
			for (size_t i = 0; i < json_array_size(doc.unsigned_items); ++i) {
				json_t* item = libssig_jades_item(
				    json_array_get(doc.unsigned_items, i)
				);
				json_t* value = json_object_get(item, "sigTst");
				bool    found = value &&
				             libssig_jades_timestamp_read(value, &stamp);
				json_decref(item);
				if (found) {
					break;
				}
			}
		}
		libssig_validation_data evidence = {0};
		status = stamp.data ? libssig_validation_document_collect(
		                          doc.cert,
		                          &stamp,
		                          params->services,
		                          &evidence
		                      )
		                    : LIBSSIG_ERROR_TIMESTAMP;
		for (size_t i = 0;
		     status == LIBSSIG_OK && i < json_array_size(doc.unsigned_items);
		     ++i) {
			json_t* item = libssig_jades_item(
			    json_array_get(doc.unsigned_items, i)
			);
			json_t* value = json_object_get(item, "arcTst");
			if (value) {
				libssig_signature previous = {0};
				status = libssig_jades_timestamp_read(value, &previous)
				             ? libssig_validation_timestamp_collect(
				                   &previous,
				                   params->services,
				                   &evidence
				               )
				             : LIBSSIG_ERROR_TIMESTAMP;
				libssig_signature_free(&previous);
			}
			json_decref(item);
		}
		if (status == LIBSSIG_OK && !evidence_add(&doc, &evidence)) {
			status = LIBSSIG_ERROR_MEMORY;
		}
		libssig_validation_free(&evidence);
	}
	libssig_signature_free(&stamp);
	if (status == LIBSSIG_OK && params->level == LIBSSIG_LEVEL_B_LTA) {
		if (!libssig_jades_archive_input(
		        &doc,
		        json_array_size(doc.unsigned_items),
		        &input
		    )) {
			status = LIBSSIG_ERROR_MEMORY;
		}
		if (status == LIBSSIG_OK) {
			status = libssig_document_stamp(
			    &input,
			    params->hash,
			    params->services,
			    &stamp
			);
		}
		if (status == LIBSSIG_OK &&
		    !libssig_jades_timestamp_add(&doc, "arcTst", &stamp)) {
			status = LIBSSIG_ERROR_MEMORY;
		}
	}
	if (status == LIBSSIG_OK && !libssig_jades_write(doc.root, output)) {
		status = LIBSSIG_ERROR_MEMORY;
	}
	libssig_signature_free(&stamp);
	libssig_signature_free(&input);
	libssig_jades_free(&doc);
	return status;
}

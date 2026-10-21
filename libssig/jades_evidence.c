/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <libssig/jades.h>
#include <stdlib.h>
#include <string.h>

libssig_status libssig_jades_v121_evidence_read(
    libssig_jades* doc,
    json_t*        value
) {
	if (!json_is_object(value) || json_object_size(value) > 2) {
		return LIBSSIG_ERROR_FORMAT;
	}
	const char* name;
	json_t*     member;
	json_object_foreach(
	    value,
	    name,
	    member
	) if (strcmp(name, "xVals") &&
	      strcmp(name, "rVals")) return LIBSSIG_ERROR_UNSUPPORTED;
	json_t* certs = json_object_get(value, "xVals");
	if (certs && (!json_is_array(certs) || !json_array_size(certs) ||
	              json_array_size(certs) > 1024)) {
		return LIBSSIG_ERROR_FORMAT;
	}
	for (size_t i = 0; i < json_array_size(certs); ++i) {
		json_t*           item = json_array_get(certs, i);
		libssig_signature bytes = {0};
		if (json_object_size(item) != 1 ||
		    !libssig_jades_v121_pki_read(
		        json_object_get(item, "x509Cert"),
		        &bytes
		    )) {
			return LIBSSIG_ERROR_FORMAT;
		}
		const unsigned char* cursor = bytes.data;
		X509*                cert = d2i_X509(NULL, &cursor, (long)bytes.len);
		bool                 ok = cert && cursor == bytes.data + bytes.len &&
		          sk_X509_num(doc->evidence.certs) < 1024 &&
		          sk_X509_push(doc->evidence.certs, cert);
		if (!ok) {
			X509_free(cert);
		}
		libssig_signature_free(&bytes);
		if (!ok) {
			return LIBSSIG_ERROR_FORMAT;
		}
	}
	json_t* revocations = json_object_get(value, "rVals");
	if (revocations &&
	    (!json_is_object(revocations) || json_object_size(revocations) > 2)) {
		return LIBSSIG_ERROR_FORMAT;
	}
	json_object_foreach(
	    revocations,
	    name,
	    member
	) if (strcmp(name, "ocspVals") &&
	      strcmp(name, "crlVals")) return LIBSSIG_ERROR_UNSUPPORTED;
	const char* kinds[] = {"ocspVals", "crlVals"};
	for (size_t j = 0; j < 2; ++j) {
		json_t* items = json_object_get(revocations, kinds[j]);
		if (items && (!json_is_array(items) || !json_array_size(items) ||
		              json_array_size(items) > 1024)) {
			return LIBSSIG_ERROR_FORMAT;
		}
		for (size_t i = 0; i < json_array_size(items); ++i) {
			libssig_signature bytes = {0};
			bool              ok = libssig_jades_v121_pki_read(
                          json_array_get(items, i),
                          &bytes
                      ) &&
			          libssig_validation_revocation_add(
			              &doc->evidence,
			              bytes.data,
			              bytes.len,
			              j == 0
			          );
			libssig_signature_free(&bytes);
			if (!ok) {
				return LIBSSIG_ERROR_FORMAT;
			}
		}
	}
	return LIBSSIG_OK;
}

/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "internal.h"
#include <libssig/xades.h>
#include <stdlib.h>
#include <string.h>

static libssig_status stamp_check(
    libssig_xades*               doc,
    xmlNode*                     node,
    bool                         archive,
    const libssig_verify_params* params,
    libssig_verify_timestamp*    result
) {
	if (!libssig_xml_prop(
	        libssig_xml_child(node, "CanonicalizationMethod", LIBSSIG_XMLDSIG),
	        "Algorithm",
	        LIBSSIG_C14N11
	    )) {
		return LIBSSIG_ERROR_UNSUPPORTED;
	}
	libssig_signature input = {0}, token = {0};
	bool              ok = libssig_xml_base64(
        libssig_xml_child(node, "EncapsulatedTimeStamp", LIBSSIG_XADES132),
        &token
    );
	ok = ok && (archive ? libssig_xades_archive_input(doc, node, &input)
	                    : libssig_xml_c14n(doc->signature_value, &input));
	libssig_status status = ok ? libssig_document_stamp_verify(
	                                 &input,
	                                 &token,
	                                 params,
	                                 result
	                             )
	                           : LIBSSIG_ERROR_TIMESTAMP;
	if (status == LIBSSIG_OK && !archive) {
		const unsigned char* cursor = token.data;
		CMS_ContentInfo*     cms = d2i_CMS_ContentInfo(
            NULL,
            &cursor,
            (long)token.len
        );
		STACK_OF(X509)* certs = cms ? CMS_get1_certs(cms) : NULL;
		status = cms ? libssig_verify_certs_append(doc->evidence.certs, certs)
		             : LIBSSIG_ERROR_TIMESTAMP;
		sk_X509_pop_free(certs, X509_free);
		CMS_ContentInfo_free(cms);
	}
	libssig_signature_free(&input);
	libssig_signature_free(&token);
	return status;
}
static libssig_status unsigned_check(
    libssig_xades*               doc,
    const libssig_verify_params* params,
    libssig_verify_result*       result
) {
	libssig_verify_signer* signer = &result->signers[0];
	xmlNode*               last_archive = NULL;
	for (xmlNode* node = doc->unsigned_properties
	                         ? doc->unsigned_properties->children
	                         : NULL;
	     node;
	     node = node->next) {
		if (libssig_xml_is(node, "ArchiveTimeStamp", LIBSSIG_XADES141)) {
			last_archive = node;
		}
	}
	libssig_verify_params selected = *params;
	if (last_archive && !(params->options & LIBSSIG_VERIFY_CURRENT_TIME)) {
		selected.options |= LIBSSIG_VERIFY_HISTORICAL;
	}
	bool validation = false;
	for (xmlNode* node = doc->unsigned_properties
	                         ? doc->unsigned_properties->children
	                         : NULL;
	     node;
	     node = node->next) {
		if (node->type != XML_ELEMENT_NODE) {
			continue;
		}
		libssig_status status = LIBSSIG_OK;
		if (libssig_xml_is(node, "AnyValidationData", LIBSSIG_XADES141)) {
			validation = true;
			status = libssig_xades_evidence_read(doc, node);
		} else if (libssig_xml_is(
		               node,
		               "SignatureTimeStamp",
		               LIBSSIG_XADES132
		           ) ||
		           libssig_xml_is(node, "ArchiveTimeStamp", LIBSSIG_XADES141)) {
			bool archive = libssig_xml_is(
			    node,
			    "ArchiveTimeStamp",
			    LIBSSIG_XADES141
			);
			if ((!archive && signer->timestamp.present) ||
			    (archive && !signer->timestamp.valid)) {
				return LIBSSIG_ERROR_FORMAT;
			}
			libssig_verify_params trust = selected;
			if (node == last_archive) {
				trust.options &= ~LIBSSIG_VERIFY_HISTORICAL;
			}
			libssig_verify_timestamp stamp = {0};
			status = stamp_check(doc, node, archive, &trust, &stamp);
			if (status == LIBSSIG_OK) {
				libssig_verify_timestamp* target = archive ? &signer->archive
				                                           : &signer->timestamp;
				free(target->cert_der);
				*target = stamp;
				stamp.cert_der = NULL;
				signer->level = archive ? LIBSSIG_LEVEL_B_LTA
				                        : LIBSSIG_LEVEL_B_T;
			}
			if (status != LIBSSIG_OK) {
				libssig_verify_timestamp* target = archive ? &signer->archive
				                                           : &signer->timestamp;
				free(target->cert_der);
				*target = stamp;
				target->present = true;
				target->status = status;
				stamp.cert_der = NULL;
			}
			free(stamp.cert_der);
		} else {
			return LIBSSIG_ERROR_UNSUPPORTED;
		}
		if (status != LIBSSIG_OK) {
			return status;
		}
		if (last_archive && node == last_archive) {
			for (xmlNode* next = node->next; next; next = next->next) {
				if (next->type == XML_ELEMENT_NODE) {
					return LIBSSIG_ERROR_EVIDENCE;
				}
			}
		}
	}
	if (validation && signer->timestamp.present && !signer->archive.present) {
		signer->level = LIBSSIG_LEVEL_B_LT;
	}
	return LIBSSIG_OK;
}
static libssig_status archives_history_check(
    libssig_xades*               doc,
    const libssig_verify_params* params,
    const libssig_verify_result* result
) {
	const libssig_verify_signer* signer = &result->signers[0];
	if (signer->level != LIBSSIG_LEVEL_B_LTA ||
	    (params->options & LIBSSIG_VERIFY_CURRENT_TIME)) {
		return LIBSSIG_OK;
	}
	xmlNode* last = NULL;
	for (xmlNode* node = doc->unsigned_properties->children; node;
	     node = node->next) {
		if (libssig_xml_is(node, "ArchiveTimeStamp", LIBSSIG_XADES141)) {
			last = node;
		}
	}
	for (xmlNode* node = doc->unsigned_properties->children;
	     node && node != last;
	     node = node->next) {
		if (libssig_xml_is(node, "ArchiveTimeStamp", LIBSSIG_XADES141)) {
			libssig_verify_timestamp stamp = {0};
			libssig_verify_params    selected = *params;
			selected.options |= LIBSSIG_VERIFY_HISTORICAL;
			libssig_status
			    status = stamp_check(doc, node, true, &selected, &stamp);
			if (status == LIBSSIG_OK) {
				status = libssig_document_evidence_stamp_check(
				    &stamp,
				    &signer->archive,
				    &doc->evidence,
				    params
				);
			}
			free(stamp.cert_der);
			if (status != LIBSSIG_OK) {
				return status;
			}
		}
	}
	return LIBSSIG_OK;
}

libssig_status libssig_xades_verify(
    const libssig_verify_params* params,
    libssig_verify_result*       result
) {
	libssig_xades     doc = {0};
	libssig_status    status = libssig_xades_read(params, &doc);
	libssig_signature input = {0};
	if (status == LIBSSIG_OK && !libssig_xml_c14n(doc.signed_info, &input)) {
		status = LIBSSIG_ERROR_CRYPTO;
	}
	if (status == LIBSSIG_OK && !libssig_document_signature_check(
	                                doc.cert,
	                                doc.algo,
	                                doc.hash,
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
		result->signature_valid = true;
		result->format = LIBSSIG_FORMAT_XADES;
		result->detached = doc.detached;
		libssig_verify_signer* signer = &result->signers[0];
		signer->level = LIBSSIG_LEVEL_B_B;
		signer->level_detected = true;
		unsigned char* der = NULL;
		int            len = i2d_X509(doc.cert, &der);
		signer->cert_der = len > 0 ? malloc((size_t)len) : NULL;
		if (!signer->cert_der) {
			status = LIBSSIG_ERROR_MEMORY;
		} else {
			memcpy(signer->cert_der, der, (size_t)len);
			signer->cert_der_len = (size_t)len;
		}
		OPENSSL_free(der);
	}
	if (status == LIBSSIG_OK) {
		status = unsigned_check(&doc, params, result);
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
	libssig_xades_free(&doc);
	return status;
}

/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <libssig/xades.h>
#include <stdlib.h>

libssig_status libssig_xades_extend(
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
	libssig_status        status = libssig_xades_verify(&verify, &result);
	libssig_level         current = result.count ? result.signers[0].level
	                                             : LIBSSIG_LEVEL_B_B;
	libssig_verify_free(&result);
	if (status != LIBSSIG_OK) {
		return status;
	}
	libssig_xades doc = {0};
	status = libssig_xades_read(&verify, &doc);
	if (status == LIBSSIG_OK && params->level != LIBSSIG_LEVEL_B_B &&
	    !doc.unsigned_properties) {
		xmlNode* q = doc.properties->parent;
		xmlNode* unsigned_props = libssig_xml_add(
		    q,
		    LIBSSIG_XADES132,
		    "UnsignedProperties",
		    NULL
		);
		doc.unsigned_properties = libssig_xml_add(
		    unsigned_props,
		    LIBSSIG_XADES132,
		    "UnsignedSignatureProperties",
		    NULL
		);
		if (!doc.unsigned_properties) {
			status = LIBSSIG_ERROR_MEMORY;
		}
	}
	libssig_signature input = {0}, stamp = {0};
	if (status == LIBSSIG_OK && params->level != LIBSSIG_LEVEL_B_B &&
	    current == LIBSSIG_LEVEL_B_B) {
		if (!libssig_xml_c14n(doc.signature_value, &input)) {
			status = LIBSSIG_ERROR_CRYPTO;
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
		    !libssig_xades_timestamp_add(&doc, false, &stamp)) {
			status = LIBSSIG_ERROR_MEMORY;
		}
		libssig_signature_free(&input);
	}
	if (status == LIBSSIG_OK && (params->level == LIBSSIG_LEVEL_B_LT ||
	                             params->level == LIBSSIG_LEVEL_B_LTA)) {
		if (!stamp.data) {
			xmlNode* existing = libssig_xml_child(
			    doc.unsigned_properties,
			    "SignatureTimeStamp",
			    LIBSSIG_XADES132
			);
			if (!libssig_xml_base64(
			        libssig_xml_child(
			            existing,
			            "EncapsulatedTimeStamp",
			            LIBSSIG_XADES132
			        ),
			        &stamp
			    )) {
				status = LIBSSIG_ERROR_TIMESTAMP;
			}
		}
		libssig_validation_data evidence = {0};
		if (status == LIBSSIG_OK) {
			status = libssig_validation_document_collect(
			    doc.cert,
			    &stamp,
			    params->services,
			    &evidence
			);
		}
		for (xmlNode* node = doc.unsigned_properties->children;
		     status == LIBSSIG_OK && node;
		     node = node->next) {
			if (libssig_xml_is(node, "ArchiveTimeStamp", LIBSSIG_XADES141)) {
				libssig_signature previous = {0};
				status = libssig_xml_base64(
				             libssig_xml_child(
				                 node,
				                 "EncapsulatedTimeStamp",
				                 LIBSSIG_XADES132
				             ),
				             &previous
				         )
				             ? libssig_validation_timestamp_collect(
				                   &previous,
				                   params->services,
				                   &evidence
				               )
				             : LIBSSIG_ERROR_TIMESTAMP;
				libssig_signature_free(&previous);
			}
		}
		if (status == LIBSSIG_OK &&
		    !libssig_xades_evidence_add(&doc, &evidence)) {
			status = LIBSSIG_ERROR_MEMORY;
		}
		libssig_validation_free(&evidence);
	}
	libssig_signature_free(&stamp);
	if (status == LIBSSIG_OK && params->level == LIBSSIG_LEVEL_B_LTA) {
		if (!libssig_xades_archive_input(&doc, NULL, &input)) {
			status = LIBSSIG_ERROR_CRYPTO;
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
		    !libssig_xades_timestamp_add(&doc, true, &stamp)) {
			status = LIBSSIG_ERROR_MEMORY;
		}
	}
	if (status == LIBSSIG_OK && !libssig_xml_write(doc.xml, output)) {
		status = LIBSSIG_ERROR_MEMORY;
	}
	libssig_signature_free(&input);
	libssig_signature_free(&stamp);
	libssig_xades_free(&doc);
	return status;
}

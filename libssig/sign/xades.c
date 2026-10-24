/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "mime.h"
#include <libssig/xades.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static xmlNode* reference_add(
    xmlNode*                 info,
    const char*              uri,
    const char*              transform,
    const libssig_signature* bytes,
    libssig_hash             hash,
    bool                     properties,
    const char*              reference_id
) {
	xmlNode* ref = libssig_xml_add(info, LIBSSIG_XMLDSIG, "Reference", NULL);
	bool     ok = ref && xmlNewProp(ref, BAD_CAST "URI", BAD_CAST uri);
	if (properties) {
		ok = ok &&
		     xmlNewProp(ref, BAD_CAST "Type", BAD_CAST LIBSSIG_PROPERTIES_TYPE);
	} else {
		ok = ok && xmlNewProp(ref, BAD_CAST "Id", BAD_CAST reference_id);
	}
	if (transform) {
		xmlNode* transforms = libssig_xml_add(
		    ref,
		    LIBSSIG_XMLDSIG,
		    "Transforms",
		    NULL
		);
		xmlNode* method = libssig_xml_add(
		    transforms,
		    LIBSSIG_XMLDSIG,
		    "Transform",
		    NULL
		);
		ok = ok && method &&
		     xmlNewProp(method, BAD_CAST "Algorithm", BAD_CAST transform);
	}
	return ok && libssig_xades_v131_digest_node(ref, bytes, hash) ? ref : NULL;
}
static bool properties_add(
    libssig_xades*             doc,
    const libssig_sign_params* params,
    const char*                mime
) {
	xmlNode*
	    object = libssig_xml_add(doc->root, LIBSSIG_XMLDSIG, "Object", NULL);
	xmlNode* q = libssig_xml_add(
	    object,
	    LIBSSIG_XADES132,
	    "QualifyingProperties",
	    NULL
	);
	char target[128];
	snprintf(target, sizeof(target), "#%s", doc->signature_id);
	bool ok = q && xmlNewProp(q, BAD_CAST "Target", BAD_CAST target);
	doc->properties = libssig_xml_add(
	    q,
	    LIBSSIG_XADES132,
	    "SignedProperties",
	    NULL
	);
	ok = ok && doc->properties &&
	     xmlNewProp(
	         doc->properties,
	         BAD_CAST "Id",
	         BAD_CAST doc->properties_id
	     );
	xmlNode* properties = libssig_xml_add(
	    doc->properties,
	    LIBSSIG_XADES132,
	    "SignedSignatureProperties",
	    NULL
	);
	char       date[21];
	time_t     now = time(NULL);
	struct tm* utc = gmtime(&now);
	ok = ok && utc && strftime(date, sizeof(date), "%Y-%m-%dT%H:%M:%SZ", utc) &&
	     libssig_xml_add(properties, LIBSSIG_XADES132, "SigningTime", date);
	xmlNode* certs = libssig_xml_add(
	    properties,
	    LIBSSIG_XADES132,
	    "SigningCertificateV2",
	    NULL
	);
	xmlNode* cert = libssig_xml_add(certs, LIBSSIG_XADES132, "Cert", NULL);
	xmlNode*
	    digest = libssig_xml_add(cert, LIBSSIG_XADES132, "CertDigest", NULL);
	libssig_signature der = {
	    .data = params->cert->der,
	    .len = params->cert->der_len
	};
	ok = ok && libssig_xades_v131_digest_node(digest, &der, params->hash);
	xmlNode* objects = libssig_xml_add(
	    doc->properties,
	    LIBSSIG_XADES132,
	    "SignedDataObjectProperties",
	    NULL
	);
	xmlNode* format = libssig_xml_add(
	    objects,
	    LIBSSIG_XADES132,
	    "DataObjectFormat",
	    NULL
	);
	snprintf(target, sizeof(target), "#%s", doc->reference_id);
	ok = ok && format &&
	     xmlNewProp(format, BAD_CAST "ObjectReference", BAD_CAST target) &&
	     libssig_xml_add(format, LIBSSIG_XADES132, "MimeType", mime);
	if (!doc->detached) {
		ok = ok && libssig_xml_add(
		               format,
		               LIBSSIG_XADES132,
		               "Encoding",
		               LIBSSIG_BASE64_TRANSFORM
		           );
	}
	return ok;
}
static bool tree_create(
    libssig_xades*             doc,
    const libssig_sign_params* params,
    const char*                mime
) {
	doc->xml = xmlNewDoc(BAD_CAST "1.0");
	doc->root = xmlNewNode(NULL, BAD_CAST "Signature");
	if (!doc->xml || !doc->root) {
		return false;
	}
	xmlDocSetRootElement(doc->xml, doc->root);
	xmlNs* ds = xmlNewNs(doc->root, BAD_CAST LIBSSIG_XMLDSIG, BAD_CAST "ds");
	xmlSetNs(doc->root, ds);
	bool ok = ds &&
	          xmlNewNs(
	              doc->root,
	              BAD_CAST LIBSSIG_XADES132,
	              BAD_CAST "xades"
	          ) &&
	          xmlNewNs(
	              doc->root,
	              BAD_CAST LIBSSIG_XADES141,
	              BAD_CAST "xades141"
	          ) &&
	          xmlNewProp(doc->root, BAD_CAST "Id", BAD_CAST doc->signature_id);
	doc->signed_info = libssig_xml_add(
	    doc->root,
	    LIBSSIG_XMLDSIG,
	    "SignedInfo",
	    NULL
	);
	xmlNode* canon = libssig_xml_add(
	    doc->signed_info,
	    LIBSSIG_XMLDSIG,
	    "CanonicalizationMethod",
	    NULL
	);
	xmlNode* method = libssig_xml_add(
	    doc->signed_info,
	    LIBSSIG_XMLDSIG,
	    "SignatureMethod",
	    NULL
	);
	ok = ok && canon && method &&
	     xmlNewProp(canon, BAD_CAST "Algorithm", BAD_CAST LIBSSIG_C14N11) &&
	     xmlNewProp(
	         method,
	         BAD_CAST "Algorithm",
	         BAD_CAST libssig_xades_v131_algo_uri(params->algo, params->hash)
	     );
	doc->signature_value = libssig_xml_add(
	    doc->root,
	    LIBSSIG_XMLDSIG,
	    "SignatureValue",
	    NULL
	);
	doc->key_info = libssig_xml_add(
	    doc->root,
	    LIBSSIG_XMLDSIG,
	    "KeyInfo",
	    NULL
	);
	xmlNode* x509 = libssig_xml_add(
	    doc->key_info,
	    LIBSSIG_XMLDSIG,
	    "X509Data",
	    NULL
	);
	char* cert = libssig_base64(
	    params->cert->der,
	    params->cert->der_len,
	    false
	);
	ok = ok && cert &&
	     libssig_xml_add(x509, LIBSSIG_XMLDSIG, "X509Certificate", cert);
	free(cert);
	doc->detached = (params->options & LIBSSIG_SIGN_DETACHED) != 0;
	if (!doc->detached) {
		doc->content_object = libssig_xml_add(
		    doc->root,
		    LIBSSIG_XMLDSIG,
		    "Object",
		    NULL
		);
		char* text = libssig_base64(params->data, params->data_len, false);
		ok = ok && text && doc->content_object &&
		     xmlNewProp(
		         doc->content_object,
		         BAD_CAST "Id",
		         BAD_CAST doc->content_id
		     ) &&
		     xmlNewProp(
		         doc->content_object,
		         BAD_CAST "MimeType",
		         BAD_CAST mime
		     ) &&
		     xmlNewProp(
		         doc->content_object,
		         BAD_CAST "Encoding",
		         BAD_CAST LIBSSIG_BASE64_TRANSFORM
		     );
		if (text && doc->content_object) {
			xmlNodeSetContent(doc->content_object, BAD_CAST text);
		}
		free(text);
	}
	ok = ok && properties_add(doc, params, mime);
	libssig_signature content = {
	    .data = (unsigned char*)params->data,
	    .len = params->data_len
	};
	char content_uri[128], properties_uri[128];
	snprintf(content_uri, sizeof(content_uri), "#%s", doc->content_id);
	snprintf(properties_uri, sizeof(properties_uri), "#%s", doc->properties_id);
	ok = ok && reference_add(
	               doc->signed_info,
	               doc->detached ? LIBSSIG_CONTENT_URI : content_uri,
	               doc->detached ? NULL : LIBSSIG_BASE64_TRANSFORM,
	               &content,
	               params->hash,
	               false,
	               doc->reference_id
	           );
	libssig_signature props = {0};
	ok = ok && libssig_xml_c14n(doc->properties, &props) &&
	     reference_add(
	         doc->signed_info,
	         properties_uri,
	         LIBSSIG_C14N11,
	         &props,
	         params->hash,
	         true,
	         doc->reference_id
	     );
	libssig_signature_free(&props);
	return ok;
}
libssig_status libssig_xades_v131_sign_named(
    const libssig_context*     ctx,
    const libssig_sign_params* params,
    const char*                identifier,
    libssig_signature*         output
) {
	char*          detected = NULL;
	libssig_status status = params->mime_type ? LIBSSIG_OK
	                                          : libssig_mime_type_detect(
	                                                params->data,
	                                                params->data_len,
	                                                &detected
	                                            );
	libssig_xades  doc = {0};
	snprintf(
	    doc.signature_id,
	    sizeof(doc.signature_id),
	    "%s",
	    identifier ? identifier : "Signature"
	);
	if (identifier) {
		snprintf(
		    doc.properties_id,
		    sizeof(doc.properties_id),
		    "%s-properties",
		    identifier
		);
		snprintf(
		    doc.reference_id,
		    sizeof(doc.reference_id),
		    "%s-reference",
		    identifier
		);
		snprintf(
		    doc.content_id,
		    sizeof(doc.content_id),
		    "%s-content",
		    identifier
		);
	} else {
		strcpy(doc.properties_id, "SignedProperties");
		strcpy(doc.reference_id, "Reference-data");
		strcpy(doc.content_id, "Content");
	}
	if (status == LIBSSIG_OK &&
	    !tree_create(
	        &doc,
	        params,
	        params->mime_type ? params->mime_type : detected
	    )) {
		status = LIBSSIG_ERROR_MEMORY;
	}
	free(detected);
	libssig_signature input = {0}, raw = {0}, baseline = {0};
	if (status == LIBSSIG_OK && !libssig_xml_c14n(doc.signed_info, &input)) {
		status = LIBSSIG_ERROR_CRYPTO;
	}
	if (status == LIBSSIG_OK) {
		status = libssig_document_sign(ctx, params, &input, &raw);
	}
	char* sig = status == LIBSSIG_OK ? libssig_base64(raw.data, raw.len, false)
	                                 : NULL;
	if (status == LIBSSIG_OK && !sig) {
		status = LIBSSIG_ERROR_MEMORY;
	}
	if (status == LIBSSIG_OK) {
		xmlNodeSetContent(doc.signature_value, BAD_CAST sig);
		if (!libssig_xml_write(doc.xml, &baseline)) {
			status = LIBSSIG_ERROR_MEMORY;
		}
	}
	free(sig);
	if (status == LIBSSIG_OK && params->level != LIBSSIG_LEVEL_B_B) {
		static const unsigned char empty = 0;
		libssig_extend_params      extend = {
		         .data = baseline.data,
		         .data_len = baseline.len,
		         .content = doc.detached ? (params->data ? params->data : &empty)
		                                 : NULL,
		         .content_len = doc.detached ? params->data_len : 0,
		         .level = params->level,
		         .hash = params->hash,
		         .services = params->services
        };
		status = libssig_xades_v131_extend(&extend, output);
	} else if (status == LIBSSIG_OK) {
		*output = baseline;
		baseline = (libssig_signature){0};
	}
	libssig_signature_free(&input);
	if (status != LIBSSIG_OK) {
		output->ck_rv = raw.ck_rv;
	}
	libssig_signature_free(&raw);
	libssig_signature_free(&baseline);
	libssig_xades_v131_free(&doc);
	return status;
}

libssig_status libssig_xades_v131_sign(
    const libssig_context*     ctx,
    const libssig_sign_params* params,
    libssig_signature*         output
) {
	return libssig_xades_v131_sign_named(ctx, params, NULL, output);
}

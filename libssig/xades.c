/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <libssig/time.h>
#include <libssig/trust.h>
#include <libssig/xades.h>
#include <libxml/hash.h>
#include <libxml/parser.h>
#include <stdlib.h>
#include <string.h>

void libssig_xades_v131_free(libssig_xades* doc) {
	xmlFreeDoc(doc->xml);
	X509_free(doc->cert);
	libssig_signature_free(&doc->content);
	libssig_signature_free(&doc->signature);
	libssig_validation_free(&doc->evidence);
	*doc = (libssig_xades){0};
}
static bool tree_valid(
    xmlNode*      node,
    size_t        depth,
    size_t*       count,
    xmlHashTable* ids
) {
	if (depth > 64) {
		return false;
	}
	for (; node; node = node->next) {
		if (++*count > 100000) {
			return false;
		}
		if (node->type == XML_ENTITY_REF_NODE ||
		    node->type == XML_ENTITY_NODE) {
			return false;
		}
		if (node->type == XML_ELEMENT_NODE) {
			xmlChar* id = xmlGetProp(node, BAD_CAST "Id");
			if (id) {
				if (!*id || xmlHashLookup(ids, id) ||
				    xmlHashAddEntry(ids, id, node)) {
					xmlFree(id);
					return false;
				}
				xmlFree(id);
			}
		}
		if (!tree_valid(node->children, depth + 1, count, ids)) {
			return false;
		}
	}
	return true;
}
static bool digest_check(xmlNode* node, const libssig_signature* bytes) {
	xmlNode* method = libssig_xml_child(node, "DigestMethod", LIBSSIG_XMLDSIG);
	libssig_hash hash = LIBSSIG_HASH_SHA256;
	bool         found = false;
	for (int i = 0; i < 3; ++i) {
		if (libssig_xml_prop(
		        method,
		        "Algorithm",
		        libssig_xades_v131_hash_uri((libssig_hash)i)
		    )) {
			hash = (libssig_hash)i;
			found = true;
		}
	}
	libssig_signature expected = {0};
	unsigned char     digest[EVP_MAX_MD_SIZE];
	unsigned int      len = 0;
	bool              ok = found &&
	          libssig_xml_base64(
	              libssig_xml_child(node, "DigestValue", LIBSSIG_XMLDSIG),
	              &expected
	          ) &&
	          libssig_document_digest(
	              bytes->data,
	              bytes->len,
	              hash,
	              digest,
	              &len
	          ) &&
	          expected.len == len && !memcmp(expected.data, digest, len);
	libssig_signature_free(&expected);
	return ok;
}
bool libssig_xades_tree_valid(xmlNode* root) {
	size_t        count = 0;
	xmlHashTable* ids = xmlHashCreate(32);
	bool          valid = ids && tree_valid(root, 0, &count, ids);
	xmlHashFree(ids, NULL);
	return valid;
}
static bool has_id(xmlNode* node) {
	xmlChar* id = node ? xmlGetProp(node, BAD_CAST "Id") : NULL;
	bool     valid = id && *id && xmlValidateNameValue(id);
	xmlFree(id);
	return valid;
}
static bool targets(xmlNode* reference, const char* key, xmlNode* target) {
	xmlChar* id = target ? xmlGetProp(target, BAD_CAST "Id") : NULL;
	xmlChar* uri = reference ? xmlGetProp(reference, BAD_CAST key) : NULL;
	bool     valid = id && uri && uri[0] == '#' && xmlStrEqual(uri + 1, id);
	xmlFree(uri);
	xmlFree(id);
	return valid;
}
static size_t elements(xmlNode* node) {
	size_t count = 0;
	for (xmlNode* child = node ? node->children : NULL; child;
	     child = child->next) {
		if (child->type == XML_ELEMENT_NODE) {
			++count;
		}
	}
	return count;
}
static bool certs_read(libssig_xades* doc) {
	xmlNode* data = libssig_xml_child(
	    doc->key_info,
	    "X509Data",
	    LIBSSIG_XMLDSIG
	);
	if (!data || elements(doc->key_info) != 1) {
		return false;
	}
	for (xmlNode* node = data->children; node; node = node->next) {
		if (node->type != XML_ELEMENT_NODE) {
			continue;
		}
		libssig_signature bytes = {0};
		if (!libssig_xml_is(node, "X509Certificate", LIBSSIG_XMLDSIG) ||
		    sk_X509_num(doc->evidence.certs) >= 1024 ||
		    !libssig_xml_base64(node, &bytes)) {
			return false;
		}
		const unsigned char* cursor = bytes.data;
		X509*                cert = d2i_X509(NULL, &cursor, (long)bytes.len);
		bool                 ok = cert && cursor == bytes.data + bytes.len &&
		          sk_X509_push(doc->evidence.certs, cert);
		if (!ok) {
			X509_free(cert);
		}
		libssig_signature_free(&bytes);
		if (!ok) {
			return false;
		}
		if (!doc->cert) {
			if (!X509_up_ref(cert)) {
				return false;
			}
			doc->cert = cert;
		}
	}
	return doc->cert != NULL;
}
static libssig_status references_read(
    const libssig_verify_params* params,
    libssig_xades*               doc
) {
	xmlNode* data = NULL;
	xmlNode* props = NULL;
	size_t   count = 0;
	for (xmlNode* n = doc->signed_info->children; n; n = n->next) {
		if (libssig_xml_is(n, "Reference", LIBSSIG_XMLDSIG)) {
			++count;
			if (libssig_xml_prop(n, "Type", LIBSSIG_PROPERTIES_TYPE)) {
				if (props) {
					return LIBSSIG_ERROR_FORMAT;
				}
				props = n;
			} else {
				if (data) {
					return LIBSSIG_ERROR_FORMAT;
				}
				data = n;
			}
		}
	}
	if (count != 2 || !data || !props || elements(doc->signed_info) != 4 ||
	    !has_id(data) || !targets(props, "URI", doc->properties)) {
		return LIBSSIG_ERROR_UNSUPPORTED;
	}
	doc->data_reference = data;
	doc->detached = libssig_xml_prop(data, "URI", LIBSSIG_CONTENT_URI);
	if (doc->detached && !params->content && !doc->signature_only) {
		return LIBSSIG_ERROR_CONTENT_REQUIRED;
	}
	if (!doc->detached && params->content) {
		return LIBSSIG_ERROR_ARGUMENT;
	}
	xmlNode* transform = libssig_xml_child(data, "Transforms", LIBSSIG_XMLDSIG);
	if (doc->detached) {
		if (transform || doc->content_object) {
			return LIBSSIG_ERROR_FORMAT;
		}
		if (!libssig_bytes_append(
		        &doc->content,
		        params->content,
		        params->content_len
		    )) {
			return LIBSSIG_ERROR_MEMORY;
		}
	} else {
		if (!targets(data, "URI", doc->content_object) ||
		    !has_id(doc->content_object) || elements(transform) != 1 ||
		    !libssig_xml_prop(
		        libssig_xml_child(transform, "Transform", LIBSSIG_XMLDSIG),
		        "Algorithm",
		        LIBSSIG_BASE64_TRANSFORM
		    ) ||
		    !libssig_xml_base64(doc->content_object, &doc->content)) {
			return LIBSSIG_ERROR_FORMAT;
		}
	}
	transform = libssig_xml_child(props, "Transforms", LIBSSIG_XMLDSIG);
	if (elements(transform) != 1 ||
	    !libssig_xml_prop(
	        libssig_xml_child(transform, "Transform", LIBSSIG_XMLDSIG),
	        "Algorithm",
	        LIBSSIG_C14N11
	    )) {
		return LIBSSIG_ERROR_UNSUPPORTED;
	}
	libssig_signature bytes = {0};
	bool              ok = libssig_xml_c14n(doc->properties, &bytes) &&
	          digest_check(props, &bytes) &&
	          (doc->signature_only || digest_check(data, &doc->content));
	libssig_signature_free(&bytes);
	return ok ? LIBSSIG_OK : LIBSSIG_ERROR_VERIFY;
}
static bool properties_valid(libssig_xades* doc) {
	xmlNode* properties = libssig_xml_child(
	    doc->properties,
	    "SignedSignatureProperties",
	    LIBSSIG_XADES132
	);
	xmlNode* time = libssig_xml_child(
	    properties,
	    "SigningTime",
	    LIBSSIG_XADES132
	);
	xmlChar* text = time ? xmlNodeGetContent(time) : NULL;
	time_t   at;
	bool     ok = text && libssig_verify_time_parse((char*)text, &at);
	xmlFree(text);
	xmlNode* certs = libssig_xml_child(
	    properties,
	    "SigningCertificateV2",
	    LIBSSIG_XADES132
	);
	xmlNode* cert = libssig_xml_child(certs, "Cert", LIBSSIG_XADES132);
	xmlNode* digest = libssig_xml_child(cert, "CertDigest", LIBSSIG_XADES132);
	unsigned char*    der = NULL;
	int               len = i2d_X509(doc->cert, &der);
	libssig_signature bytes = {.data = der, .len = len > 0 ? (size_t)len : 0};
	ok = ok && elements(certs) == 1 && len > 0 && digest_check(digest, &bytes);
	OPENSSL_free(der);
	xmlNode* objects = libssig_xml_child(
	    doc->properties,
	    "SignedDataObjectProperties",
	    LIBSSIG_XADES132
	);
	xmlNode* format = libssig_xml_child(
	    objects,
	    "DataObjectFormat",
	    LIBSSIG_XADES132
	);
	return ok && elements(objects) == 1 &&
	       targets(format, "ObjectReference", doc->data_reference) &&
	       libssig_xml_child(format, "MimeType", LIBSSIG_XADES132);
}
libssig_status libssig_xades_v131_read(
    const libssig_verify_params* params,
    libssig_xades*               doc
) {
	if (params->data_len > LIBSSIG_DOCUMENT_LIMIT) {
		return LIBSSIG_ERROR_FORMAT;
	}
	doc->xml = xmlReadMemory(
	    (char*)params->data,
	    (int)params->data_len,
	    NULL,
	    NULL,
	    XML_PARSE_NONET | XML_PARSE_NOERROR | XML_PARSE_NOWARNING
	);
	if (!doc->xml || doc->xml->intSubset || doc->xml->extSubset) {
		return LIBSSIG_ERROR_FORMAT;
	}
	doc->root = xmlDocGetRootElement(doc->xml);
	size_t        count = 0;
	xmlHashTable* ids = xmlHashCreate(32);
	bool          valid = ids && tree_valid(doc->root, 0, &count, ids);
	xmlHashFree(ids, NULL);
	if (!valid || !libssig_xml_is(doc->root, "Signature", LIBSSIG_XMLDSIG) ||
	    !has_id(doc->root)) {
		return LIBSSIG_ERROR_UNSUPPORTED;
	}
	doc->signed_info = libssig_xml_child(
	    doc->root,
	    "SignedInfo",
	    LIBSSIG_XMLDSIG
	);
	doc->signature_value = libssig_xml_child(
	    doc->root,
	    "SignatureValue",
	    LIBSSIG_XMLDSIG
	);
	doc->key_info = libssig_xml_child(doc->root, "KeyInfo", LIBSSIG_XMLDSIG);
	xmlNode* qualifying = NULL;
	size_t   object_count = 0;
	for (xmlNode* n = doc->root->children; n; n = n->next) {
		if (libssig_xml_is(n, "Object", LIBSSIG_XMLDSIG)) {
			++object_count;
			xmlNode* q = libssig_xml_child(
			    n,
			    "QualifyingProperties",
			    LIBSSIG_XADES132
			);
			if (q) {
				if (qualifying || elements(n) != 1) {
					return LIBSSIG_ERROR_FORMAT;
				}
				qualifying = q;
			} else {
				if (doc->content_object) {
					return LIBSSIG_ERROR_FORMAT;
				}
				doc->content_object = n;
			}
		}
	}
	if (!qualifying || !targets(qualifying, "Target", doc->root) ||
	    elements(doc->root) != 3 + object_count) {
		return LIBSSIG_ERROR_FORMAT;
	}
	doc->properties = libssig_xml_child(
	    qualifying,
	    "SignedProperties",
	    LIBSSIG_XADES132
	);
	doc->unsigned_properties = libssig_xml_child(
	    libssig_xml_child(qualifying, "UnsignedProperties", LIBSSIG_XADES132),
	    "UnsignedSignatureProperties",
	    LIBSSIG_XADES132
	);
	if (!has_id(doc->properties) || !libssig_xml_prop(
	                                    libssig_xml_child(
	                                        doc->signed_info,
	                                        "CanonicalizationMethod",
	                                        LIBSSIG_XMLDSIG
	                                    ),
	                                    "Algorithm",
	                                    LIBSSIG_C14N11
	                                )) {
		return LIBSSIG_ERROR_UNSUPPORTED;
	}
	xmlNode* method = libssig_xml_child(
	    doc->signed_info,
	    "SignatureMethod",
	    LIBSSIG_XMLDSIG
	);
	bool found = false;
	for (int i = 0; i < 3; ++i) {
		for (int j = 0; j < 3; ++j) {
			if (libssig_xml_prop(
			        method,
			        "Algorithm",
			        libssig_xades_v131_algo_uri(
			            (libssig_algo)i,
			            (libssig_hash)j
			        )
			    )) {
				doc->algo = (libssig_algo)i;
				doc->hash = (libssig_hash)j;
				found = true;
			}
		}
	}
	if (!found || elements(method)) {
		return LIBSSIG_ERROR_UNSUPPORTED;
	}
	doc->evidence.certs = sk_X509_new_null();
	doc->evidence.revocations = sk_ASN1_TYPE_new_null();
	if (!doc->evidence.certs || !doc->evidence.revocations) {
		return LIBSSIG_ERROR_MEMORY;
	}
	if (!certs_read(doc) ||
	    !libssig_xml_base64(doc->signature_value, &doc->signature)) {
		return LIBSSIG_ERROR_FORMAT;
	}
	libssig_status status = references_read(params, doc);
	if (status == LIBSSIG_OK && !properties_valid(doc)) {
		status = LIBSSIG_ERROR_VERIFY;
	}
	return status;
}
bool libssig_xades_v131_archive_input(
    const libssig_xades* doc,
    xmlNode*             stop,
    libssig_signature*   bytes
) {
	bool ok = libssig_bytes_append(
	              bytes,
	              doc->content.data,
	              doc->content.len
	          ) &&
	          libssig_xml_c14n(doc->properties, bytes) &&
	          libssig_xml_c14n(doc->signed_info, bytes) &&
	          libssig_xml_c14n(doc->signature_value, bytes) &&
	          libssig_xml_c14n(doc->key_info, bytes);
	for (xmlNode* n = doc->unsigned_properties
	                      ? doc->unsigned_properties->children
	                      : NULL;
	     ok && n && n != stop;
	     n = n->next) {
		if (n->type == XML_ELEMENT_NODE) {
			ok = libssig_xml_c14n(n, bytes);
		}
	}
	if (ok && doc->content_object) {
		ok = libssig_xml_c14n(doc->content_object, bytes);
	}
	return ok;
}

bool libssig_xades_v131_timestamp_add(
    libssig_xades*           doc,
    bool                     archive,
    const libssig_signature* token
) {
	xmlNode* stamp = libssig_xml_add(
	    doc->unsigned_properties,
	    archive ? LIBSSIG_XADES141 : LIBSSIG_XADES132,
	    archive ? "ArchiveTimeStamp" : "SignatureTimeStamp",
	    NULL
	);
	xmlNode* canon = libssig_xml_add(
	    stamp,
	    LIBSSIG_XMLDSIG,
	    "CanonicalizationMethod",
	    NULL
	);
	char* text = libssig_base64(token->data, token->len, false);
	bool  ok = canon && text &&
	          xmlNewProp(
	              canon,
	              BAD_CAST "Algorithm",
	              BAD_CAST LIBSSIG_C14N11
	          ) &&
	          libssig_xml_add(
	              stamp,
	              LIBSSIG_XADES132,
	              "EncapsulatedTimeStamp",
	              text
	          );
	free(text);
	return ok;
}

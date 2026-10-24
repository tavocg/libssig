/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <libssig/ades.h>
#include <libssig/jades.h>
#include <libssig/multisign.h>
#include <libssig/xades.h>
#include <libxml/parser.h>
#include <stdlib.h>
#include <string.h>

#define MAX_SIGNERS 1024
#define MAX_VIEWS (64u * 1024u * 1024u)

void libssig_multisign_free(libssig_multisign* doc) {
	for (size_t i = 0; i < doc->count; ++i) {
		libssig_signature_free(&doc->parts[i]);
	}
	free(doc->parts);
	*doc = (libssig_multisign){0};
}
static libssig_status append(libssig_multisign* doc, libssig_signature* part) {
	if (doc->count == MAX_SIGNERS || part->len > MAX_VIEWS - doc->bytes) {
		return LIBSSIG_ERROR_UNSUPPORTED;
	}
	libssig_signature* parts = realloc(
	    doc->parts,
	    (doc->count + 1) * sizeof(*parts)
	);
	if (!parts) {
		return LIBSSIG_ERROR_MEMORY;
	}
	doc->parts = parts;
	doc->bytes += part->len;
	doc->parts[doc->count++] = *part;
	*part = (libssig_signature){0};
	return LIBSSIG_OK;
}
static bool raw_write(libssig_raw_cms* cms, libssig_signature* out) {
	int length = i2d_libssig_raw_cms(cms, NULL);
	if (length <= 0 || !(out->data = malloc((size_t)length))) {
		return false;
	}
	unsigned char* cursor = out->data;
	if (i2d_libssig_raw_cms(cms, &cursor) != length) {
		libssig_signature_free(out);
		return false;
	}
	out->len = (size_t)length;
	return true;
}
/* A co-signer may append shared certificates/revocations. A historical view
 * must expose only the material covered by this signer's archive hash index;
 * otherwise unprotected additions could become historical trust evidence. */
static void protected_stack(
    STACK_OF(ASN1_TYPE) * values,
    const STACK_OF(ASN1_OCTET_STRING) * hashes,
    const EVP_MD* md
) {
	for (int i = sk_ASN1_TYPE_num(values) - 1; i >= 0; --i) {
		unsigned char* der = NULL;
		int            len = i2d_ASN1_TYPE(sk_ASN1_TYPE_value(values, i), &der);
		unsigned char  digest[EVP_MAX_MD_SIZE];
		unsigned int   size = 0;
		bool           found = false;
		if (len > 0 && EVP_Digest(der, (size_t)len, digest, &size, md, NULL)) {
			for (int j = 0; j < sk_ASN1_OCTET_STRING_num(hashes); ++j) {
				const ASN1_OCTET_STRING* hash = sk_ASN1_OCTET_STRING_value(
				    hashes,
				    j
				);
				if (ASN1_STRING_length(hash) == (int)size &&
				    !memcmp(ASN1_STRING_get0_data(hash), digest, size)) {
					found = true;
					break;
				}
			}
		}
		OPENSSL_free(der);
		if (!found) {
			ASN1_TYPE_free(sk_ASN1_TYPE_delete(values, i));
		}
	}
}
static void cms_protected_view(libssig_raw_cms* raw, CMS_SignerInfo* signer) {
	ASN1_OBJECT* archive_oid = OBJ_txt2obj(LIBSSIG_ARCHIVE_OID, 1);
	ASN1_OBJECT* index_oid = OBJ_txt2obj(LIBSSIG_HASH_INDEX_OID, 1);
	libssig_cades_v131_hash_index* selected = NULL;
	int                            pos = -1;
	while (archive_oid && index_oid &&
	       (pos = CMS_unsigned_get_attr_by_OBJ(signer, archive_oid, pos)) >=
	           0) {
		X509_ATTRIBUTE*      attr = CMS_unsigned_get_attr(signer, pos);
		const ASN1_TYPE*     value = X509_ATTRIBUTE_count(attr) == 1
		                                 ? X509_ATTRIBUTE_get0_type(attr, 0)
		                                 : NULL;
		const unsigned char* cursor = value && value->type == V_ASN1_SEQUENCE
		                                  ? ASN1_STRING_get0_data(
		                                        value->value.sequence
		                                    )
		                                  : NULL;
		CMS_ContentInfo*     token = cursor ? d2i_CMS_ContentInfo(
                                              NULL,
                                              &cursor,
                                              ASN1_STRING_length(
                                                  value->value.sequence
                                              )
                                          )
		                                    : NULL;
		STACK_OF(CMS_SignerInfo)* signers = token ? CMS_get0_SignerInfos(token)
		                                          : NULL;
		CMS_SignerInfo* tsa = sk_CMS_SignerInfo_num(signers) == 1
		                          ? sk_CMS_SignerInfo_value(signers, 0)
		                          : NULL;
		int n = tsa ? CMS_unsigned_get_attr_by_OBJ(tsa, index_oid, -1) : -1;
		X509_ATTRIBUTE*  index_attr = n >= 0 ? CMS_unsigned_get_attr(tsa, n)
		                                     : NULL;
		const ASN1_TYPE* encoded = index_attr &&
		                                   X509_ATTRIBUTE_count(index_attr) == 1
		                               ? X509_ATTRIBUTE_get0_type(index_attr, 0)
		                               : NULL;
		libssig_cades_v131_hash_index* index = NULL;
		if (encoded && encoded->type == V_ASN1_SEQUENCE) {
			cursor = ASN1_STRING_get0_data(encoded->value.sequence);
			index = d2i_libssig_cades_v131_hash_index(
			    NULL,
			    &cursor,
			    ASN1_STRING_length(encoded->value.sequence)
			);
		}
		if (index &&
		    (!selected || sk_ASN1_OCTET_STRING_num(index->attributes) >
		                      sk_ASN1_OCTET_STRING_num(selected->attributes))) {
			libssig_cades_v131_hash_index_free(selected);
			selected = index;
			index = NULL;
		}
		libssig_cades_v131_hash_index_free(index);
		CMS_ContentInfo_free(token);
	}
	if (selected) {
		const EVP_MD* md = EVP_get_digestbyobj(selected->algorithm->algorithm);
		if (md) {
			protected_stack(raw->signed_data->certs, selected->certs, md);
			protected_stack(
			    raw->signed_data->revocations,
			    selected->revocations,
			    md
			);
		}
	}
	libssig_cades_v131_hash_index_free(selected);
	ASN1_OBJECT_free(archive_oid);
	ASN1_OBJECT_free(index_oid);
}
void libssig_multisign_protected_view(libssig_signature* part) {
	const unsigned char* cursor = part->data;
	CMS_ContentInfo* cms = d2i_CMS_ContentInfo(NULL, &cursor, (long)part->len);
	STACK_OF(CMS_SignerInfo)* signers = cms ? CMS_get0_SignerInfos(cms) : NULL;
	libssig_raw_cms* raw = cms && sk_CMS_SignerInfo_num(signers) == 1
	                           ? libssig_cms_decode(cms)
	                           : NULL;
	if (raw) {
		cms_protected_view(raw, sk_CMS_SignerInfo_value(signers, 0));
		libssig_signature encoded = {0};
		if (raw_write(raw, &encoded)) {
			libssig_signature_free(part);
			*part = encoded;
		}
	}
	libssig_raw_cms_free(raw);
	CMS_ContentInfo_free(cms);
}
static libssig_status cms_read(
    const unsigned char* bytes,
    size_t               length,
    libssig_multisign*   doc
) {
	const unsigned char* cursor = bytes;
	CMS_ContentInfo*     cms = d2i_CMS_ContentInfo(NULL, &cursor, (long)length);
	if (!cms || cursor != bytes + length ||
	    OBJ_obj2nid(CMS_get0_type(cms)) != NID_pkcs7_signed) {
		CMS_ContentInfo_free(cms);
		return LIBSSIG_ERROR_NOT_FOUND;
	}
	doc->format = LIBSSIG_FORMAT_CMS;
	STACK_OF(CMS_SignerInfo)* signers = CMS_get0_SignerInfos(cms);
	for (int i = 0; i < sk_CMS_SignerInfo_num(signers); ++i) {
		CMS_SignerInfo* signer = sk_CMS_SignerInfo_value(signers, i);
		if (CMS_signed_get_attr_by_NID(
		        signer,
		        NID_id_smime_aa_signingCertificateV2,
		        -1
		    ) >= 0 ||
		    CMS_signed_get_attr_by_NID(
		        signer,
		        NID_id_smime_aa_signingCertificate,
		        -1
		    ) >= 0) {
			doc->format = LIBSSIG_FORMAT_CADES;
		}
	}
	libssig_raw_cms* raw = libssig_cms_decode(cms);
	CMS_ContentInfo_free(cms);
	int count = raw ? sk_ASN1_TYPE_num(raw->signed_data->signers) : 0;
	libssig_status status = count > 0 && count <= MAX_SIGNERS
	                            ? LIBSSIG_OK
	                            : LIBSSIG_ERROR_FORMAT;
	doc->collection = count > 1;
	for (int i = 0; status == LIBSSIG_OK && i < count; ++i) {
		libssig_raw_cms* one = ASN1_item_dup(
		    ASN1_ITEM_rptr(libssig_raw_cms),
		    raw
		);
		if (!one) {
			status = LIBSSIG_ERROR_MEMORY;
			break;
		}
		for (int n = count - 1; n >= 0; --n) {
			if (n != i) {
				ASN1_TYPE_free(
				    sk_ASN1_TYPE_delete(one->signed_data->signers, n)
				);
			}
		}
		libssig_signature part = {0};
		status = raw_write(one, &part) ? append(doc, &part)
		                               : LIBSSIG_ERROR_MEMORY;
		libssig_signature_free(&part);
		libssig_raw_cms_free(one);
	}
	libssig_raw_cms_free(raw);
	return status;
}
static libssig_status json_read(
    const unsigned char* bytes,
    size_t               length,
    libssig_multisign*   doc
) {
	json_t* root = json_loadb(
	    (const char*)bytes,
	    length,
	    JSON_REJECT_DUPLICATES,
	    NULL
	);
	json_t* signatures = json_object_get(root, "signatures");
	bool    single = json_is_string(json_object_get(root, "protected")) &&
	              json_is_string(json_object_get(root, "signature"));
	if (!signatures && !single) {
		json_decref(root);
		return LIBSSIG_ERROR_NOT_FOUND;
	}
	doc->format = LIBSSIG_FORMAT_JADES;
	doc->collection = signatures != NULL;
	size_t         count = single ? 1 : json_array_size(signatures);
	libssig_status status = count && count <= MAX_SIGNERS &&
	                                (!signatures ||
	                                 (json_is_array(signatures) &&
	                                  json_object_size(root) ==
	                                      (json_object_get(root, "payload")
	                                           ? 2u
	                                           : 1u)))
	                            ? LIBSSIG_OK
	                            : LIBSSIG_ERROR_FORMAT;
	for (size_t i = 0; status == LIBSSIG_OK && i < count; ++i) {
		json_t* flat = json_deep_copy(
		    single ? root : json_array_get(signatures, i)
		);
		json_t* payload = json_object_get(root, "payload");
		if (!json_is_object(flat) ||
		    (!single && json_object_get(flat, "payload")) ||
		    (payload && json_object_set(flat, "payload", payload))) {
			status = LIBSSIG_ERROR_FORMAT;
		}
		libssig_signature part = {0};
		if (status == LIBSSIG_OK) {
			status = libssig_jades_v121_write(flat, &part)
			             ? append(doc, &part)
			             : LIBSSIG_ERROR_MEMORY;
		}
		libssig_signature_free(&part);
		json_decref(flat);
	}
	json_decref(root);
	return status;
}
static libssig_status xml_read(
    const unsigned char* bytes,
    size_t               length,
    libssig_multisign*   doc
) {
	xmlDoc* xml = xmlReadMemory(
	    (const char*)bytes,
	    (int)length,
	    NULL,
	    NULL,
	    XML_PARSE_NONET | XML_PARSE_NOERROR | XML_PARSE_NOWARNING
	);
	xmlNode* root = xml ? xmlDocGetRootElement(xml) : NULL;
	bool     single = libssig_xml_is(root, "Signature", LIBSSIG_XMLDSIG);
	bool     collection = root && !root->ns &&
	                  xmlStrEqual(root->name, BAD_CAST "Signatures");
	if (!single && !collection) {
		xmlFreeDoc(xml);
		return LIBSSIG_ERROR_NOT_FOUND;
	}
	doc->format = LIBSSIG_FORMAT_XADES;
	doc->collection = collection;
	libssig_status status = xml->intSubset || xml->extSubset ||
	                                !libssig_xades_tree_valid(root) ||
	                                (collection &&
	                                 (root->properties || root->nsDef))
	                            ? LIBSSIG_ERROR_FORMAT
	                            : LIBSSIG_OK;
	for (xmlNode* node = single ? root : root->children;
	     status == LIBSSIG_OK && node;
	     node = single ? NULL : node->next) {
		if (node->type != XML_ELEMENT_NODE) {
			if (node->type != XML_TEXT_NODE || !xmlIsBlankNode(node)) {
				status = LIBSSIG_ERROR_FORMAT;
			}
			continue;
		}
		if (!libssig_xml_is(node, "Signature", LIBSSIG_XMLDSIG)) {
			status = LIBSSIG_ERROR_FORMAT;
			break;
		}
		xmlDoc*           one = xmlNewDoc(BAD_CAST "1.0");
		xmlNode*          copy = one ? xmlDocCopyNode(node, one, 1) : NULL;
		libssig_signature part = {0};
		if (copy) {
			xmlDocSetRootElement(one, copy);
		}
		status = copy && libssig_xml_write(one, &part) ? append(doc, &part)
		                                               : LIBSSIG_ERROR_MEMORY;
		libssig_signature_free(&part);
		xmlFreeDoc(one);
	}
	if (!doc->count && status == LIBSSIG_OK) {
		status = LIBSSIG_ERROR_FORMAT;
	}
	xmlFreeDoc(xml);
	return status;
}
libssig_status libssig_multisign_read(
    const unsigned char* bytes,
    size_t               length,
    libssig_multisign*   doc
) {
	*doc = (libssig_multisign){0};
	if (!bytes || !length || length > LIBSSIG_DOCUMENT_LIMIT) {
		return LIBSSIG_ERROR_NOT_FOUND;
	}
	libssig_format format = libssig_document_format(bytes, length);
	libssig_status status = format == LIBSSIG_FORMAT_JADES
	                            ? json_read(bytes, length, doc)
	                        : format == LIBSSIG_FORMAT_XADES
	                            ? xml_read(bytes, length, doc)
	                        : format == LIBSSIG_FORMAT_PADES
	                            ? LIBSSIG_ERROR_NOT_FOUND
	                            : cms_read(bytes, length, doc);
	if (status != LIBSSIG_OK) {
		libssig_multisign_free(doc);
	}
	return status;
}
static bool merge_stack(
    STACK_OF(ASN1_TYPE) * *destination,
    STACK_OF(ASN1_TYPE) * source,
    bool unique
) {
	if (!*destination && !(*destination = sk_ASN1_TYPE_new_null())) {
		return false;
	}
	while (sk_ASN1_TYPE_num(source) > 0) {
		ASN1_TYPE* item = sk_ASN1_TYPE_shift(source);
		bool       found = false;
		for (int i = 0; unique && i < sk_ASN1_TYPE_num(*destination); ++i) {
			if (!ASN1_TYPE_cmp(item, sk_ASN1_TYPE_value(*destination, i))) {
				found = true;
				break;
			}
		}
		if (found) {
			ASN1_TYPE_free(item);
		} else if (!sk_ASN1_TYPE_push(*destination, item)) {
			ASN1_TYPE_free(item);
			return false;
		}
	}
	return true;
}
static libssig_status cms_merge(
    const libssig_multisign* doc,
    libssig_signature*       output
) {
	libssig_raw_cms* merged = NULL;
	libssig_status   status = LIBSSIG_OK;
	for (size_t i = 0; status == LIBSSIG_OK && i < doc->count; ++i) {
		const unsigned char* cursor = doc->parts[i].data;
		libssig_raw_cms*     part = d2i_libssig_raw_cms(
            NULL,
            &cursor,
            (long)doc->parts[i].len
        );
		if (!part) {
			status = LIBSSIG_ERROR_FORMAT;
			break;
		}
		if (!merged) {
			merged = part;
			continue;
		}
		libssig_raw_signed_data *a = merged->signed_data,
		                        *b = part->signed_data;
		if (ASN1_TYPE_cmp(a->content, b->content)) {
			status = LIBSSIG_ERROR_ARGUMENT;
		}
		if (status == LIBSSIG_OK &&
		    (!merge_stack(&a->algorithms, b->algorithms, true) ||
		     !merge_stack(&a->certs, b->certs, true) ||
		     !merge_stack(&a->revocations, b->revocations, true) ||
		     !merge_stack(&a->signers, b->signers, false))) {
			status = LIBSSIG_ERROR_MEMORY;
		}
		if (ASN1_INTEGER_get(b->version) > ASN1_INTEGER_get(a->version)) {
			ASN1_INTEGER_set(a->version, ASN1_INTEGER_get(b->version));
		}
		libssig_raw_cms_free(part);
	}
	if (status == LIBSSIG_OK && !raw_write(merged, output)) {
		status = LIBSSIG_ERROR_MEMORY;
	}
	libssig_raw_cms_free(merged);
	return status;
}
libssig_status libssig_multisign_merge(
    const libssig_multisign* doc,
    libssig_signature*       output
) {
	if (!doc->count) {
		return LIBSSIG_ERROR_ARGUMENT;
	}
	if (doc->format == LIBSSIG_FORMAT_CADES ||
	    doc->format == LIBSSIG_FORMAT_CMS) {
		return cms_merge(doc, output);
	}
	if (doc->format == LIBSSIG_FORMAT_JADES) {
		json_t*        root = json_object();
		json_t*        signatures = json_array();
		libssig_status status = root && signatures ? LIBSSIG_OK
		                                           : LIBSSIG_ERROR_MEMORY;
		for (size_t i = 0; status == LIBSSIG_OK && i < doc->count; ++i) {
			json_t* flat = json_loadb(
			    (char*)doc->parts[i].data,
			    doc->parts[i].len,
			    JSON_REJECT_DUPLICATES,
			    NULL
			);
			json_t* payload = json_object_get(flat, "payload");
			if (i == 0 && payload) {
				json_object_set(root, "payload", payload);
			}
			if (!flat ||
			    ((payload || json_object_get(root, "payload")) &&
			     !json_equal(payload, json_object_get(root, "payload")))) {
				status = LIBSSIG_ERROR_ARGUMENT;
			}
			if (flat) {
				json_object_del(flat, "payload");
			}
			if (status == LIBSSIG_OK && json_array_append(signatures, flat)) {
				status = LIBSSIG_ERROR_MEMORY;
			}
			json_decref(flat);
		}
		if (status == LIBSSIG_OK &&
		    (json_object_set(root, "signatures", signatures) ||
		     !libssig_jades_v121_write(root, output))) {
			status = LIBSSIG_ERROR_MEMORY;
		}
		json_decref(signatures);
		json_decref(root);
		return status;
	}
	xmlDoc*  xml = xmlNewDoc(BAD_CAST "1.0");
	xmlNode* root = xml ? xmlNewNode(NULL, BAD_CAST "Signatures") : NULL;
	if (!root) {
		xmlFreeDoc(xml);
		return LIBSSIG_ERROR_MEMORY;
	}
	xmlDocSetRootElement(xml, root);
	libssig_status status = LIBSSIG_OK;
	for (size_t i = 0; status == LIBSSIG_OK && i < doc->count; ++i) {
		xmlDoc* part = xmlReadMemory(
		    (char*)doc->parts[i].data,
		    (int)doc->parts[i].len,
		    NULL,
		    NULL,
		    XML_PARSE_NONET | XML_PARSE_NOERROR | XML_PARSE_NOWARNING
		);
		xmlNode* node = part
		                    ? xmlDocCopyNode(xmlDocGetRootElement(part), xml, 1)
		                    : NULL;
		if (!node || !xmlAddChild(root, node)) {
			status = LIBSSIG_ERROR_MEMORY;
		}
		xmlFreeDoc(part);
	}
	if (status == LIBSSIG_OK && !libssig_xml_write(xml, output)) {
		status = LIBSSIG_ERROR_MEMORY;
	}
	xmlFreeDoc(xml);
	return status;
}
libssig_status libssig_multisign_content(
    const libssig_multisign* doc,
    const unsigned char*     detached,
    size_t                   detached_len,
    libssig_signature*       content,
    bool*                    is_detached
) {
	libssig_status status = LIBSSIG_OK;
	for (size_t i = 0; status == LIBSSIG_OK && i < doc->count; ++i) {
		libssig_verify_params params = {
		    .data = doc->parts[i].data,
		    .data_len = doc->parts[i].len,
		    .content = detached,
		    .content_len = detached_len
		};
		libssig_signature bytes = {0};
		bool              separate = false;
		if (doc->format == LIBSSIG_FORMAT_JADES) {
			libssig_jades part = {0};
			status = libssig_jades_v121_read(&params, &part);
			separate = !json_object_get(part.root, "payload");
			if (status == LIBSSIG_OK && !libssig_base64_read(
			                                part.payload,
			                                strlen(part.payload),
			                                true,
			                                &bytes
			                            )) {
				status = LIBSSIG_ERROR_FORMAT;
			}
			libssig_jades_v121_free(&part);
		} else if (doc->format == LIBSSIG_FORMAT_XADES) {
			libssig_xades part = {0};
			status = libssig_xades_v131_read(&params, &part);
			separate = part.detached;
			bytes = part.content;
			part.content = (libssig_signature){0};
			libssig_xades_v131_free(&part);
		} else {
			const unsigned char* cursor = params.data;
			CMS_ContentInfo*     cms = d2i_CMS_ContentInfo(
                NULL,
                &cursor,
                (long)params.data_len
            );
			ASN1_OCTET_STRING** payload = cms ? CMS_get0_content(cms) : NULL;
			separate = cms && CMS_is_detached(cms);
			const unsigned char* data = separate ? detached
			                            : payload && *payload
			                                ? ASN1_STRING_get0_data(*payload)
			                                : NULL;
			size_t               size = separate ? detached_len
			                            : payload && *payload
			                                ? (size_t)ASN1_STRING_length(*payload)
			                                : 0;
			status = !cms                    ? LIBSSIG_ERROR_FORMAT
			         : separate && !detached ? LIBSSIG_ERROR_CONTENT_REQUIRED
			         : !separate && detached ? LIBSSIG_ERROR_ARGUMENT
			         : libssig_bytes_append(&bytes, data, size)
			             ? LIBSSIG_OK
			             : LIBSSIG_ERROR_MEMORY;
			CMS_ContentInfo_free(cms);
		}
		if (status == LIBSSIG_OK && i &&
		    (separate != *is_detached || bytes.len != content->len ||
		     (bytes.len && memcmp(bytes.data, content->data, bytes.len)))) {
			status = LIBSSIG_ERROR_ARGUMENT;
		}
		if (status == LIBSSIG_OK && !i) {
			*content = bytes;
			bytes = (libssig_signature){0};
			*is_detached = separate;
		}
		libssig_signature_free(&bytes);
	}
	return status;
}
libssig_status libssig_verify_append(
    libssig_verify_result* result,
    libssig_verify_result* item
) {
	if (item->count > MAX_SIGNERS - result->count) {
		return LIBSSIG_ERROR_UNSUPPORTED;
	}
	libssig_verify_signer* signers = realloc(
	    result->signers,
	    (result->count + item->count) * sizeof(*signers)
	);
	if (!signers && item->count) {
		return LIBSSIG_ERROR_MEMORY;
	}
	bool first = result->count == 0;
	result->signers = signers;
	if (item->count) {
		memcpy(
		    signers + result->count,
		    item->signers,
		    item->count * sizeof(*signers)
		);
	}
	result->count += item->count;
	result->signature_valid = item->signature_valid &&
	                          (first || result->signature_valid);
	result->trusted = item->trusted && (first || result->trusted);
	result->trust_checked = item->trust_checked &&
	                        (first || result->trust_checked);
	result->detached = item->detached;
	free(item->signers);
	*item = (libssig_verify_result){0};
	return LIBSSIG_OK;
}

void libssig_multisign_failure(
    const libssig_verify_params* params,
    libssig_status               status,
    libssig_verify_result*       result
) {
	if (result->count) {
		return;
	}
	libssig_verify_signer* signer = calloc(1, sizeof(*signer));
	if (!signer) {
		return;
	}
	result->signers = signer;
	result->count = 1;
	signer->checked = true;
	signer->status = status;
	result->format = libssig_document_format(params->data, params->data_len);
	X509*            cert = NULL;
	libssig_xades    xml = {0};
	libssig_jades    json = {0};
	CMS_ContentInfo* cms = NULL;
	STACK_OF(X509)* certs = NULL;
	if (result->format == LIBSSIG_FORMAT_XADES) {
		libssig_xades_v131_read(params, &xml);
		cert = xml.cert;
	} else if (result->format == LIBSSIG_FORMAT_JADES) {
		libssig_jades_v121_read(params, &json);
		cert = json.cert;
	} else {
		const unsigned char* cursor = params->data;
		cms = d2i_CMS_ContentInfo(NULL, &cursor, (long)params->data_len);
		certs = cms ? CMS_get1_certs(cms) : NULL;
		if (cms && certs && CMS_set1_signers_certs(cms, certs, 0)) {
			STACK_OF(CMS_SignerInfo)* signers = CMS_get0_SignerInfos(cms);
			if (sk_CMS_SignerInfo_num(signers) == 1) {
				CMS_SignerInfo_get0_algs(
				    sk_CMS_SignerInfo_value(signers, 0),
				    NULL,
				    &cert,
				    NULL,
				    NULL
				);
			}
		}
	}
	int length = cert ? i2d_X509(cert, NULL) : 0;
	if (length > 0 && (signer->cert_der = malloc((size_t)length))) {
		unsigned char* cursor = signer->cert_der;
		if (i2d_X509(cert, &cursor) == length) {
			signer->cert_der_len = (size_t)length;
		}
	}
	sk_X509_pop_free(certs, X509_free);
	CMS_ContentInfo_free(cms);
	libssig_xades_v131_free(&xml);
	libssig_jades_v121_free(&json);
}

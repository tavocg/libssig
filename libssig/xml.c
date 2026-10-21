/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <libssig/xades.h>
#include <libxml/c14n.h>
#include <libxml/xpath.h>
#include <stdlib.h>
#include <string.h>

bool libssig_xml_is(xmlNode* node, const char* name, const char* ns) {
	return node && node->type == XML_ELEMENT_NODE &&
	       xmlStrEqual(node->name, BAD_CAST name) && node->ns &&
	       xmlStrEqual(node->ns->href, BAD_CAST ns);
}
xmlNode* libssig_xml_child(xmlNode* parent, const char* name, const char* ns) {
	xmlNode* found = NULL;
	for (xmlNode* n = parent ? parent->children : NULL; n; n = n->next) {
		if (libssig_xml_is(n, name, ns)) {
			if (found) {
				return NULL;
			}
			found = n;
		}
	}
	return found;
}
bool libssig_xml_prop(xmlNode* node, const char* name, const char* value) {
	xmlChar* text = node ? xmlGetProp(node, BAD_CAST name) : NULL;
	bool     ok = text && xmlStrEqual(text, BAD_CAST value);
	xmlFree(text);
	return ok;
}
xmlNode* libssig_xml_add(
    xmlNode*    parent,
    const char* ns,
    const char* name,
    const char* content
) {
	xmlNs* space = parent ? xmlSearchNsByHref(parent->doc, parent, BAD_CAST ns)
	                      : NULL;
	return parent && space ? xmlNewTextChild(
	                             parent,
	                             space,
	                             BAD_CAST name,
	                             content ? BAD_CAST content : NULL
	                         )
	                       : NULL;
}
bool libssig_xml_c14n(xmlNode* node, libssig_signature* bytes) {
	if (!node) {
		return false;
	}
	xmlXPathContext* ctx = xmlXPathNewContext(node->doc);
	if (ctx) {
		ctx->node = node;
	}
	xmlXPathObject* set = ctx ? xmlXPathEvalExpression(
	                                BAD_CAST
	                                "(. | .//node() | .//@* | .//namespace::*)",
	                                ctx
	                            )
	                          : NULL;
	xmlChar*        encoded = NULL;
	int             len = set ? xmlC14NDocDumpMemory(
                        node->doc,
                        set->nodesetval,
                        XML_C14N_1_1,
                        NULL,
                        0,
                        &encoded
                    )
	                          : -1;
	bool ok = len >= 0 && libssig_bytes_append(bytes, encoded, (size_t)len);
	xmlFree(encoded);
	xmlXPathFreeObject(set);
	xmlXPathFreeContext(ctx);
	return ok;
}
bool libssig_xml_base64(xmlNode* node, libssig_signature* bytes) {
	if (!node) {
		return false;
	}
	for (xmlNode* child = node->children; child; child = child->next) {
		if (child->type != XML_TEXT_NODE &&
		    child->type != XML_CDATA_SECTION_NODE) {
			return false;
		}
	}
	xmlChar* text = xmlNodeGetContent(node);
	if (!text) {
		return false;
	}
	size_t count = 0;
	for (size_t i = 0; text[i]; ++i) {
		if (text[i] != ' ' && text[i] != '\n' && text[i] != '\r' &&
		    text[i] != '\t') {
			text[count++] = text[i];
		}
	}
	bool ok = libssig_base64_read((char*)text, count, false, bytes);
	xmlFree(text);
	return ok;
}
bool libssig_xml_write(xmlDoc* doc, libssig_signature* bytes) {
	xmlChar* data = NULL;
	int      len = 0;
	xmlDocDumpMemoryEnc(doc, &data, &len, "UTF-8");
	bool ok = len > 0 && libssig_bytes_append(bytes, data, (size_t)len);
	xmlFree(data);
	return ok;
}
const char* libssig_xades_hash_uri(libssig_hash hash) {
	const char* uris[] = {
	    "http://www.w3.org/2001/04/xmlenc#sha256",
	    "http://www.w3.org/2001/04/xmldsig-more#sha384",
	    "http://www.w3.org/2001/04/xmlenc#sha512"
	};
	return hash >= 0 && hash <= LIBSSIG_HASH_SHA512 ? uris[hash] : NULL;
}
const char* libssig_xades_algo_uri(libssig_algo algo, libssig_hash hash) {
	const char* uris[3][3] = {
	    {"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
	     "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
	     "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"},
	    {"http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1",
	     "http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1",
	     "http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1"},
	    {"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
	     "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384",
	     "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"}
	};
	return algo >= 0 && algo <= LIBSSIG_ALGO_ECDSA && hash >= 0 &&
	               hash <= LIBSSIG_HASH_SHA512
	           ? uris[algo][hash]
	           : NULL;
}
bool libssig_xades_digest_node(
    xmlNode*                 parent,
    const libssig_signature* bytes,
    libssig_hash             hash
) {
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int  len = 0;
	if (!libssig_document_digest(bytes->data, bytes->len, hash, digest, &len)) {
		return false;
	}
	char* text = libssig_base64(digest, len, false);
	xmlNode*
	    method = libssig_xml_add(parent, LIBSSIG_XMLDSIG, "DigestMethod", NULL);
	bool ok = text && method &&
	          xmlNewProp(
	              method,
	              BAD_CAST "Algorithm",
	              BAD_CAST libssig_xades_hash_uri(hash)
	          ) &&
	          libssig_xml_add(parent, LIBSSIG_XMLDSIG, "DigestValue", text);
	free(text);
	return ok;
}

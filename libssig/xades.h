/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef LIBSSIG_XADES_H
#define LIBSSIG_XADES_H
#include <libssig/document.h>
#include <libxml/tree.h>
#define LIBSSIG_XMLDSIG "http://www.w3.org/2000/09/xmldsig#"
#define LIBSSIG_XADES132 "http://uri.etsi.org/01903/v1.3.2#"
#define LIBSSIG_XADES141 "http://uri.etsi.org/01903/v1.4.1#"
#define LIBSSIG_C14N11 "http://www.w3.org/2006/12/xml-c14n11"
#define LIBSSIG_BASE64_TRANSFORM LIBSSIG_XMLDSIG "base64"
#define LIBSSIG_PROPERTIES_TYPE "http://uri.etsi.org/01903#SignedProperties"
#define LIBSSIG_CONTENT_URI "urn:libssig:content"
typedef struct {
	xmlDoc*  xml;
	xmlNode *root, *signed_info, *signature_value, *key_info, *properties,
	    *unsigned_properties, *content_object;
	X509*                   cert;
	libssig_algo            algo;
	libssig_hash            hash;
	bool                    detached;
	bool                    signature_only;
	libssig_signature       content, signature;
	libssig_validation_data evidence;
} libssig_xades;
void     libssig_xades_free(libssig_xades* doc);
xmlNode* libssig_xml_child(xmlNode* parent, const char* name, const char* ns);
bool     libssig_xml_is(xmlNode* node, const char* name, const char* ns);
bool     libssig_xml_prop(xmlNode* node, const char* name, const char* value);
xmlNode* libssig_xml_add(
    xmlNode*    parent,
    const char* ns,
    const char* name,
    const char* content
);
bool        libssig_xml_c14n(xmlNode* node, libssig_signature* bytes);
bool        libssig_xml_base64(xmlNode* node, libssig_signature* bytes);
bool        libssig_xml_write(xmlDoc* doc, libssig_signature* bytes);
const char* libssig_xades_hash_uri(libssig_hash hash);
const char* libssig_xades_algo_uri(libssig_algo algo, libssig_hash hash);
bool        libssig_xades_digest_node(
           xmlNode*                 parent,
           const libssig_signature* bytes,
           libssig_hash             hash
       );
libssig_status libssig_xades_read(
    const libssig_verify_params* params,
    libssig_xades*               doc
);
bool libssig_xades_archive_input(
    const libssig_xades* doc,
    xmlNode*             stop,
    libssig_signature*   bytes
);
libssig_status libssig_xades_evidence_read(libssig_xades* doc, xmlNode* value);
bool           libssig_xades_evidence_add(
              libssig_xades*                 doc,
              const libssig_validation_data* evidence
          );
bool libssig_xades_timestamp_add(
    libssig_xades*           doc,
    bool                     archive,
    const libssig_signature* token
);
#endif

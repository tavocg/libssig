/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <libssig/xades.h>
#include <stdlib.h>

libssig_status libssig_xades_v131_evidence_read(
    libssig_xades* doc,
    xmlNode*       value
) {
	for (xmlNode* group = value->children; group; group = group->next) {
		if (group->type != XML_ELEMENT_NODE) {
			continue;
		}
		bool certs = libssig_xml_is(
		    group,
		    "CertificateValues",
		    LIBSSIG_XADES132
		);
		bool revocations = libssig_xml_is(
		    group,
		    "RevocationValues",
		    LIBSSIG_XADES132
		);
		if (!certs && !revocations) {
			return LIBSSIG_ERROR_UNSUPPORTED;
		}
		for (xmlNode* n = group->children; n; n = n->next) {
			if (n->type != XML_ELEMENT_NODE) {
				continue;
			}
			if (certs) {
				libssig_signature bytes = {0};
				if (!libssig_xml_is(
				        n,
				        "EncapsulatedX509Certificate",
				        LIBSSIG_XADES132
				    ) ||
				    !libssig_xml_base64(n, &bytes)) {
					return LIBSSIG_ERROR_FORMAT;
				}
				const unsigned char* cursor = bytes.data;
				X509* cert = d2i_X509(NULL, &cursor, (long)bytes.len);
				bool  ok = cert && cursor == bytes.data + bytes.len &&
				          sk_X509_num(doc->evidence.certs) < 1024 &&
				          sk_X509_push(doc->evidence.certs, cert);
				if (!ok) {
					X509_free(cert);
				}
				libssig_signature_free(&bytes);
				if (!ok) {
					return LIBSSIG_ERROR_FORMAT;
				}
			} else {
				bool ocsp = libssig_xml_is(n, "OCSPValues", LIBSSIG_XADES132);
				if (!ocsp &&
				    !libssig_xml_is(n, "CRLValues", LIBSSIG_XADES132)) {
					return LIBSSIG_ERROR_UNSUPPORTED;
				}
				for (xmlNode* item = n->children; item; item = item->next) {
					if (item->type != XML_ELEMENT_NODE) {
						continue;
					}
					libssig_signature bytes = {0};
					bool              ok = libssig_xml_is(
                                  item,
                                  ocsp ? "EncapsulatedOCSPValue"
					                                : "EncapsulatedCRLValue",
                                  LIBSSIG_XADES132
                              ) &&
					          libssig_xml_base64(item, &bytes) &&
					          libssig_validation_revocation_add(
					              &doc->evidence,
					              bytes.data,
					              bytes.len,
					              ocsp
					          );
					libssig_signature_free(&bytes);
					if (!ok) {
						return LIBSSIG_ERROR_FORMAT;
					}
				}
			}
		}
	}
	return LIBSSIG_OK;
}
bool libssig_xades_v131_evidence_add(
    libssig_xades*                 doc,
    const libssig_validation_data* evidence
) {
	xmlNode* data = libssig_xml_add(
	    doc->unsigned_properties,
	    LIBSSIG_XADES141,
	    "AnyValidationData",
	    NULL
	);
	xmlNode* certs = NULL;
	bool     ok = data != NULL;
	for (int i = 0; ok && i < sk_X509_num(evidence->certs); ++i) {
		X509* cert = sk_X509_value(evidence->certs, i);
		if (X509_cmp(cert, doc->cert) == 0) {
			continue;
		}
		if (!certs) {
			certs = libssig_xml_add(
			    data,
			    LIBSSIG_XADES132,
			    "CertificateValues",
			    NULL
			);
		}
		unsigned char* der = NULL;
		int            len = i2d_X509(cert, &der);
		char* text = len > 0 ? libssig_base64(der, (size_t)len, false) : NULL;
		ok = text && libssig_xml_add(
		                 certs,
		                 LIBSSIG_XADES132,
		                 "EncapsulatedX509Certificate",
		                 text
		             );
		free(text);
		OPENSSL_free(der);
	}
	xmlNode *revocations = NULL, *ocsp_values = NULL, *crl_values = NULL;
	for (int i = 0; ok && i < sk_ASN1_TYPE_num(evidence->revocations); ++i) {
		libssig_signature bytes = {0};
		bool              ocsp = false;
		ok = libssig_validation_revocation_read(
		    sk_ASN1_TYPE_value(evidence->revocations, i),
		    &bytes,
		    &ocsp
		);
		if (!revocations) {
			revocations = libssig_xml_add(
			    data,
			    LIBSSIG_XADES132,
			    "RevocationValues",
			    NULL
			);
		}
		xmlNode** group = ocsp ? &ocsp_values : &crl_values;
		if (!*group) {
			*group = libssig_xml_add(
			    revocations,
			    LIBSSIG_XADES132,
			    ocsp ? "OCSPValues" : "CRLValues",
			    NULL
			);
		}
		char* text = ok ? libssig_base64(bytes.data, bytes.len, false) : NULL;
		ok = text &&
		     libssig_xml_add(
		         *group,
		         LIBSSIG_XADES132,
		         ocsp ? "EncapsulatedOCSPValue" : "EncapsulatedCRLValue",
		         text
		     );
		free(text);
		libssig_signature_free(&bytes);
	}
	/* RevocationValues schema requires CRLValues before OCSPValues. */
	if (crl_values && ocsp_values && crl_values->prev) {
		xmlUnlinkNode(crl_values);
		xmlAddPrevSibling(ocsp_values, crl_values);
	}
	return ok;
}

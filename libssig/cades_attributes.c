/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <libssig/cms_internal.h>
#include <openssl/asn1t.h>
#include <openssl/ess.h>
#include <string.h>

/* CMS signs a universal DER SET OF, not the context-specific [0] wrapper. */
ASN1_ITEM_TEMPLATE(libssig_signed_attributes) = ASN1_EX_TEMPLATE_TYPE(
    ASN1_TFLG_SET_ORDER,
    0,
    libssig_signed_attributes,
    X509_ATTRIBUTE
) static_ASN1_ITEM_TEMPLATE_END(libssig_signed_attributes)

    static bool certificate_attribute_add(
        CMS_SignerInfo * signer,
        X509*         cert,
        const EVP_MD* digest
    ) {
	ESS_SIGNING_CERT_V2*
	    ess = OSSL_ESS_signing_cert_v2_new_init(digest, cert, NULL, 0);
	if (!ess) {
		return false;
	}

	ASN1_STRING* sequence = ASN1_item_pack(
	    ess,
	    ASN1_ITEM_rptr(ESS_SIGNING_CERT_V2),
	    NULL
	);
	bool ok = sequence && CMS_signed_add1_attr_by_NID(
	                          signer,
	                          NID_id_smime_aa_signingCertificateV2,
	                          V_ASN1_SEQUENCE,
	                          sequence,
	                          -1
	                      ) > 0;
	ASN1_STRING_free(sequence);
	ESS_SIGNING_CERT_V2_free(ess);
	return ok;
}

static bool content_attributes_add(
    CMS_SignerInfo*                signer,
    const libssig_key_sign_params* params,
    const EVP_MD*                  digest
) {
	unsigned char       hash[EVP_MAX_MD_SIZE];
	unsigned int        len = 0;
	const unsigned char empty = 0;
	const void*         data = params->data ? params->data : &empty;
	if (EVP_Digest(data, params->data_len, hash, &len, digest, NULL) != 1) {
		return false;
	}

	return CMS_signed_add1_attr_by_NID(
	           signer,
	           NID_pkcs9_contentType,
	           V_ASN1_OBJECT,
	           OBJ_nid2obj(NID_pkcs7_data),
	           -1
	       ) > 0 &&
	       CMS_signed_add1_attr_by_NID(
	           signer,
	           NID_pkcs9_messageDigest,
	           V_ASN1_OCTET_STRING,
	           hash,
	           (int)len
	       ) > 0;
}

static bool time_attribute_add(CMS_SignerInfo* signer) {
	ASN1_TIME* time = X509_gmtime_adj(NULL, 0);
	bool       ok = time && CMS_signed_add1_attr_by_NID(
                          signer,
                          NID_pkcs9_signingTime,
                          ASN1_STRING_type(time),
                          time,
                          -1
                      ) > 0;
	ASN1_TIME_free(time);
	return ok;
}

static bool mime_attribute_add(CMS_SignerInfo* signer, const char* type) {
	if (!type) {
		return false;
	}

	size_t len = strlen(type);
	if (!len || len > 255 || !strchr(type, '/')) {
		return false;
	}

	for (size_t i = 0; i < len; ++i) {
		if ((unsigned char)type[i] < 0x20 || (unsigned char)type[i] > 0x7e) {
			return false;
		}
	}
	ASN1_OBJECT* oid = OBJ_txt2obj(LIBSSIG_CADES_MIME_TYPE_OID, 1);
	bool         ok = oid && CMS_signed_add1_attr_by_OBJ(
                         signer,
                         oid,
                         V_ASN1_UTF8STRING,
                         type,
                         (int)len
                     ) > 0;
	ASN1_OBJECT_free(oid);
	return ok;
}

bool libssig_cades_attributes_add(
    CMS_SignerInfo*                signer,
    X509*                          cert,
    const libssig_key_sign_params* params,
    const EVP_MD*                  digest
) {
	return content_attributes_add(signer, params, digest) &&
	       certificate_attribute_add(signer, cert, digest) &&
	       time_attribute_add(signer) &&
	       mime_attribute_add(signer, params->mime_type);
}

static STACK_OF(X509_ATTRIBUTE) * attributes_take(CMS_SignerInfo* signer) {
	STACK_OF(X509_ATTRIBUTE)* attributes = sk_X509_ATTRIBUTE_new_null();
	if (!attributes) {
		return NULL;
	}

	while (CMS_signed_get_attr_count(signer) > 0) {
		X509_ATTRIBUTE* attribute = CMS_signed_delete_attr(signer, 0);
		if (!attribute || !sk_X509_ATTRIBUTE_push(attributes, attribute)) {
			X509_ATTRIBUTE_free(attribute);
			sk_X509_ATTRIBUTE_pop_free(attributes, X509_ATTRIBUTE_free);
			return NULL;
		}
	}
	return attributes;
}

static bool attributes_restore(
    CMS_SignerInfo* signer,
    STACK_OF(X509_ATTRIBUTE) * attributes
) {
	for (int i = 0; i < sk_X509_ATTRIBUTE_num(attributes); ++i) {
		if (!CMS_signed_add1_attr(
		        signer,
		        sk_X509_ATTRIBUTE_value(attributes, i)
		    )) {
			return false;
		}
	}
	return true;
}

unsigned char* libssig_cades_attributes_encode(
    CMS_SignerInfo* signer,
    size_t*         out_len
) {
	*out_len = 0;
	STACK_OF(X509_ATTRIBUTE)* attributes = attributes_take(signer);
	if (!attributes) {
		return NULL;
	}

	unsigned char* der = NULL;
	int            len = ASN1_item_i2d(
        (ASN1_VALUE*)attributes,
        &der,
        ASN1_ITEM_rptr(libssig_signed_attributes)
    );
	/* Restore canonical order so in-memory and serialized verification agree.
	 */
	bool ok = len > 0 && attributes_restore(signer, attributes);
	sk_X509_ATTRIBUTE_pop_free(attributes, X509_ATTRIBUTE_free);
	if (!ok) {
		OPENSSL_free(der);
		return NULL;
	}
	*out_len = (size_t)len;
	return der;
}

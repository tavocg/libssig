/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <libssig/libssig.h>
#include <limits.h>
#include <openssl/cms.h>
#include <openssl/cmserr.h>
#include <openssl/err.h>
#include <openssl/ess.h>
#include <openssl/x509v3.h>
#include <stdlib.h>
#include <string.h>

void libssig_verify_free(libssig_verify_result* result) {
	if (!result) {
		return;
	}

	for (size_t i = 0; i < result->count; ++i) {
		free(result->signers[i].cert_der);
		free(result->signers[i].mime_type);
	}
	free(result->signers);
	*result = (libssig_verify_result){0};
}

/* Reject duplicate attributes and multiple values instead of choosing one. */
static ASN1_TYPE* attribute_get(CMS_SignerInfo* s, int nid, bool* valid) {
	int i = CMS_signed_get_attr_by_NID(s, nid, -1);
	if (i < 0) {
		return NULL;
	}

	X509_ATTRIBUTE* attr = CMS_signed_get_attr(s, i);
	if (CMS_signed_get_attr_by_NID(s, nid, i) >= 0 ||
	    X509_ATTRIBUTE_count(attr) != 1) {
		*valid = false;
		return NULL;
	}
	return X509_ATTRIBUTE_get0_type(attr, 0);
}

static bool ess_check(CMS_SignerInfo* s, X509* cert, STACK_OF(X509) * certs) {
	bool       valid = true;
	ASN1_TYPE* v1 = attribute_get(
	    s,
	    NID_id_smime_aa_signingCertificate,
	    &valid
	);
	ASN1_TYPE* v2 = attribute_get(
	    s,
	    NID_id_smime_aa_signingCertificateV2,
	    &valid
	);
	if (!valid || (v1 && v1->type != V_ASN1_SEQUENCE) ||
	    (v2 && v2->type != V_ASN1_SEQUENCE)) {
		return false;
	}

	if (!v1 && !v2) {
		return true;
	}

	ESS_SIGNING_CERT*    first = NULL;
	ESS_SIGNING_CERT_V2* second = NULL;
	if (v1) {
		const unsigned char* cursor = ASN1_STRING_get0_data(v1->value.sequence);
		long                 len = ASN1_STRING_length(v1->value.sequence);
		const unsigned char* end = cursor + len;
		first = d2i_ESS_SIGNING_CERT(NULL, &cursor, len);
		valid = first && cursor == end;
	}

	if (v2) {
		const unsigned char* cursor = ASN1_STRING_get0_data(v2->value.sequence);
		long                 len = ASN1_STRING_length(v2->value.sequence);
		const unsigned char* end = cursor + len;
		second = d2i_ESS_SIGNING_CERT_V2(NULL, &cursor, len);
		valid = valid && second && cursor == end;
	}

	STACK_OF(X509)* chain = sk_X509_new_null();
	valid = valid && chain && sk_X509_push(chain, cert);
	for (int i = 0; valid && i < sk_X509_num(certs); ++i) {
		X509* item = sk_X509_value(certs, i);
		if (X509_cmp(item, cert) != 0 && !sk_X509_push(chain, item)) {
			valid = false;
		}
	}

	valid = valid && OSSL_ESS_check_signing_certs(first, second, chain, 1) == 1;
	sk_X509_free(chain);
	ESS_SIGNING_CERT_free(first);
	ESS_SIGNING_CERT_V2_free(second);
	return valid;
}

static libssig_status mime_copy(CMS_SignerInfo* s, char** out_type) {
	ASN1_OBJECT* oid = OBJ_txt2obj("0.4.0.1733.2.1", 1);
	if (!oid) {
		return LIBSSIG_ERROR_MEMORY;
	}

	int i = CMS_signed_get_attr_by_OBJ(s, oid, -1);
	int next = i < 0 ? -1 : CMS_signed_get_attr_by_OBJ(s, oid, i);
	ASN1_OBJECT_free(oid);
	if (i < 0) {
		return LIBSSIG_OK;
	}

	X509_ATTRIBUTE* attr = CMS_signed_get_attr(s, i);
	if (next >= 0 || X509_ATTRIBUTE_count(attr) != 1) {
		return LIBSSIG_ERROR_VERIFY;
	}

	ASN1_TYPE* value = X509_ATTRIBUTE_get0_type(attr, 0);
	if (!value || value->type != V_ASN1_UTF8STRING) {
		return LIBSSIG_ERROR_VERIFY;
	}

	int                  len = ASN1_STRING_length(value->value.utf8string);
	const unsigned char* data = ASN1_STRING_get0_data(value->value.utf8string);
	if (len <= 0 || len > 255 || memchr(data, 0, (size_t)len)) {
		return LIBSSIG_ERROR_VERIFY;
	}

	for (int i = 0; i < len; ++i) {
		if (data[i] < 0x20 || data[i] > 0x7e) {
			return LIBSSIG_ERROR_VERIFY;
		}
	}

	*out_type = malloc((size_t)len + 1);
	if (!*out_type) {
		return LIBSSIG_ERROR_MEMORY;
	}
	memcpy(*out_type, data, (size_t)len);
	(*out_type)[len] = '\0';
	return LIBSSIG_OK;
}

static libssig_status signer_copy(
    CMS_SignerInfo* s,
    STACK_OF(X509) * certs,
    libssig_verify_signer* signer
) {
	X509* cert = NULL;
	CMS_SignerInfo_get0_algs(s, NULL, &cert, NULL, NULL);
	if (!cert || !ess_check(s, cert, certs)) {
		return LIBSSIG_ERROR_VERIFY;
	}

	int len = i2d_X509(cert, NULL);
	if (len <= 0) {
		return LIBSSIG_ERROR_CRYPTO;
	}

	signer->cert_der = malloc((size_t)len);
	if (!signer->cert_der) {
		return LIBSSIG_ERROR_MEMORY;
	}

	unsigned char* cursor = signer->cert_der;
	if (i2d_X509(cert, &cursor) != len) {
		return LIBSSIG_ERROR_CRYPTO;
	}
	signer->cert_der_len = (size_t)len;
	return mime_copy(s, &signer->mime_type);
}

static libssig_status signature_error(void) {
	libssig_status status = LIBSSIG_ERROR_VERIFY;
	unsigned long  error;
	while ((error = ERR_get_error()) != 0) {
		int reason = ERR_GET_REASON(error);
		if ((ERR_GET_LIB(error) == ERR_LIB_CMS &&
		     (reason == CMS_R_UNKNOWN_DIGEST_ALGORITHM
#ifdef CMS_R_UNSUPPORTED_SIGNATURE_ALGORITHM
		      || reason == CMS_R_UNSUPPORTED_SIGNATURE_ALGORITHM
#endif
)) ||
		    reason == ERR_R_UNSUPPORTED) {
			status = LIBSSIG_ERROR_UNSUPPORTED;
		}
	}
	return status;
}

static libssig_status signatures_check(
    CMS_ContentInfo*             cms,
    const libssig_verify_params* params,
    libssig_verify_result*       result
) {
	result->detached = CMS_is_detached(cms) == 1;
	if (result->detached && !params->content) {
		return LIBSSIG_ERROR_CONTENT_REQUIRED;
	}

	if (!result->detached && params->content) {
		return LIBSSIG_ERROR_ARGUMENT;
	}

	BIO* input = result->detached ? BIO_new_mem_buf(
	                                    params->content,
	                                    (int)params->content_len
	                                )
	                              : NULL;
	if (result->detached && !input) {
		return LIBSSIG_ERROR_MEMORY;
	}

	ERR_clear_error();
	int ok = CMS_verify(
	    cms,
	    NULL,
	    NULL,
	    input,
	    NULL,
	    CMS_BINARY | CMS_NO_SIGNER_CERT_VERIFY
	);
	BIO_free(input);
	if (ok != 1) {
		return signature_error();
	}

	STACK_OF(CMS_SignerInfo)* signers = CMS_get0_SignerInfos(cms);
	int count = sk_CMS_SignerInfo_num(signers);
	if (count <= 0) {
		return LIBSSIG_ERROR_FORMAT;
	}

	result->signers = calloc((size_t)count, sizeof(*result->signers));
	if (!result->signers) {
		return LIBSSIG_ERROR_MEMORY;
	}
	result->count = (size_t)count;

	STACK_OF(X509)* certs = CMS_get1_certs(cms);
	libssig_status status = LIBSSIG_OK;
	for (int i = 0; i < count && status == LIBSSIG_OK; ++i) {
		status = signer_copy(
		    sk_CMS_SignerInfo_value(signers, i),
		    certs,
		    &result->signers[i]
		);
	}
	sk_X509_pop_free(certs, X509_free);
	result->signature_valid = status == LIBSSIG_OK;
	return status;
}

static libssig_status signer_trust_check(
    CMS_SignerInfo* s,
    X509_STORE*     store,
    STACK_OF(X509) * certs,
    libssig_verify_signer* signer
) {
	X509* cert = NULL;
	CMS_SignerInfo_get0_algs(s, NULL, &cert, NULL, NULL);
	X509_STORE_CTX* ctx = X509_STORE_CTX_new();
	if (!ctx || !X509_STORE_CTX_init(ctx, store, cert, certs)) {
		X509_STORE_CTX_free(ctx);
		return LIBSSIG_ERROR_CRYPTO;
	}

	/* Document signatures do not imply S/MIME certificate purpose. */
	int ok = X509_verify_cert(ctx);
	signer->trust_error = X509_STORE_CTX_get_error(ctx);
	X509_STORE_CTX_free(ctx);
	return ok == 1 ? LIBSSIG_OK : LIBSSIG_ERROR_TRUST;
}

static libssig_status trust_check(
    CMS_ContentInfo*       cms,
    libssig_verify_result* result
) {
	X509_STORE* store = X509_STORE_new();
	if (!store) {
		return LIBSSIG_ERROR_MEMORY;
	}

	if (X509_STORE_set_default_paths(store) != 1) {
		X509_STORE_free(store);
		return LIBSSIG_ERROR_TRUST;
	}

	STACK_OF(X509)* certs = CMS_get1_certs(cms);
	STACK_OF(CMS_SignerInfo)* signers = CMS_get0_SignerInfos(cms);
	libssig_status status = LIBSSIG_OK;
	result->trust_checked = true;
	result->trusted = true;
	for (size_t i = 0; i < result->count; ++i) {
		libssig_status checked = signer_trust_check(
		    sk_CMS_SignerInfo_value(signers, (int)i),
		    store,
		    certs,
		    &result->signers[i]
		);
		if (checked != LIBSSIG_OK) {
			result->trusted = false;
			status = checked;
			if (checked != LIBSSIG_ERROR_TRUST) {
				break;
			}
		}
	}
	sk_X509_pop_free(certs, X509_free);
	X509_STORE_free(store);
	return status;
}

libssig_status libssig_verify(
    const libssig_verify_params* params,
    libssig_verify_result*       result
) {
	if (!result) {
		return LIBSSIG_ERROR_ARGUMENT;
	}

	*result = (libssig_verify_result){0};
	if (!params || !params->data || !params->data_len ||
	    params->data_len > LONG_MAX || params->content_len > INT_MAX ||
	    (!params->content && params->content_len) ||
	    (params->options & ~LIBSSIG_VERIFY_SYSTEM_TRUST)) {
		return LIBSSIG_ERROR_ARGUMENT;
	}

	const unsigned char* cursor = params->data;
	CMS_ContentInfo*     cms = d2i_CMS_ContentInfo(
        NULL,
        &cursor,
        (long)params->data_len
    );
	if (!cms || cursor != params->data + params->data_len) {
		CMS_ContentInfo_free(cms);
		return LIBSSIG_ERROR_FORMAT;
	}

	libssig_status status = OBJ_obj2nid(CMS_get0_type(cms)) == NID_pkcs7_signed
	                            ? signatures_check(cms, params, result)
	                            : LIBSSIG_ERROR_UNSUPPORTED;
	if (status == LIBSSIG_OK &&
	    (params->options & LIBSSIG_VERIFY_SYSTEM_TRUST)) {
		status = trust_check(cms, result);
	}
	CMS_ContentInfo_free(cms);
	if (status != LIBSSIG_OK && status != LIBSSIG_ERROR_TRUST) {
		libssig_verify_free(result);
	}
	return status;
}

/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <libssig/trust.h>
#include <openssl/ess.h>
#include <openssl/pem.h>
#include <string.h>

static bool space_is(unsigned char c) {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' ||
	       c == '\v';
}

static libssig_status certificate_push(STACK_OF(X509) * certs, X509* cert) {
	if (!cert) {
		return LIBSSIG_ERROR_FORMAT;
	}

	if (!sk_X509_push(certs, cert)) {
		X509_free(cert);
		return LIBSSIG_ERROR_MEMORY;
	}
	return LIBSSIG_OK;
}

static libssig_status pem_parse(
    const unsigned char* data,
    size_t               len,
    STACK_OF(X509) * certs
) {
	static const char header[] = "-----BEGIN CERTIFICATE-----";
	while (len) {
		while (len && space_is(*data)) {
			++data;
			--len;
		}

		if (!len) {
			break;
		}

		if (len < sizeof(header) - 1 ||
		    memcmp(data, header, sizeof(header) - 1)) {
			return LIBSSIG_ERROR_FORMAT;
		}

		BIO* input = BIO_new_mem_buf(data, (int)len);
		if (!input) {
			return LIBSSIG_ERROR_MEMORY;
		}

		X509*  cert = PEM_read_bio_X509(input, NULL, NULL, NULL);
		size_t remaining = BIO_ctrl_pending(input);
		BIO_free(input);
		libssig_status status = certificate_push(certs, cert);
		if (status != LIBSSIG_OK) {
			return status;
		}
		data += len - remaining;
		len = remaining;
	}
	return sk_X509_num(certs) ? LIBSSIG_OK : LIBSSIG_ERROR_FORMAT;
}

libssig_status libssig_verify_certs_parse(
    const unsigned char* data,
    size_t               len,
    STACK_OF(X509) * *out_certs
) {
	*out_certs = sk_X509_new_null();
	if (!*out_certs) {
		return LIBSSIG_ERROR_MEMORY;
	}

	if (!data) {
		return LIBSSIG_OK;
	}

	const unsigned char* cursor = data;
	while (cursor < data + len && space_is(*cursor)) {
		++cursor;
	}

	if (cursor < data + len && *cursor == '-') {
		return pem_parse(data, len, *out_certs);
	}

	cursor = data;
	X509* cert = d2i_X509(NULL, &cursor, (long)len);
	if (!cert || cursor != data + len) {
		X509_free(cert);
		return LIBSSIG_ERROR_FORMAT;
	}
	return certificate_push(*out_certs, cert);
}

libssig_status libssig_verify_certs_append(
    STACK_OF(X509) * certs,
    const STACK_OF(X509) * extra
) {
	for (int i = 0; i < sk_X509_num(extra); ++i) {
		X509* cert = sk_X509_value(extra, i);
		if (!X509_up_ref(cert)) {
			return LIBSSIG_ERROR_MEMORY;
		}

		libssig_status status = certificate_push(certs, cert);
		if (status != LIBSSIG_OK) {
			return status;
		}
	}
	return LIBSSIG_OK;
}

libssig_status libssig_verify_store_create(
    const libssig_verify_params* params,
    const STACK_OF(X509) * roots,
    X509_STORE** out_store
) {
	*out_store = X509_STORE_new();
	if (!*out_store) {
		return LIBSSIG_ERROR_MEMORY;
	}

	if ((params->options & LIBSSIG_VERIFY_SYSTEM_TRUST) &&
	    X509_STORE_set_default_paths(*out_store) != 1) {
		return LIBSSIG_ERROR_TRUST;
	}

	for (int i = 0; i < sk_X509_num(roots); ++i) {
		if (!X509_STORE_add_cert(*out_store, sk_X509_value(roots, i))) {
			return LIBSSIG_ERROR_CRYPTO;
		}
	}
	return LIBSSIG_OK;
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

bool libssig_verify_ess_check(
    CMS_SignerInfo* s,
    X509*           cert,
    STACK_OF(X509) * certs
) {
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

bool libssig_ocsp_buffer_valid(
    const unsigned char* data,
    size_t               len,
    bool                 required
) {
	return len <= INT_MAX && ((data && len) || (!required && !data && !len));
}

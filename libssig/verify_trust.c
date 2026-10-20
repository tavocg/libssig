/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <libssig/verify_internal.h>
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

libssig_status libssig_verify_trust_check(
    CMS_ContentInfo*             cms,
    const libssig_verify_params* params,
    const STACK_OF(X509) * roots,
    STACK_OF(X509) * certs,
    libssig_verify_result* result
) {
	X509_STORE*    store = NULL;
	libssig_status status = libssig_verify_store_create(params, roots, &store);
	if (status != LIBSSIG_OK) {
		X509_STORE_free(store);
		return status;
	}

	STACK_OF(CMS_SignerInfo)* signers = CMS_get0_SignerInfos(cms);
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
	X509_STORE_free(store);
	return status;
}

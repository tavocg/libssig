/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "internal.h"
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

libssig_status libssig_ocsp_certificate(
    const unsigned char* data,
    size_t               len,
    X509**               out_cert
) {
	STACK_OF(X509)* certs = NULL;
	libssig_status status = libssig_verify_certs_parse(data, len, &certs);
	if (status == LIBSSIG_OK && sk_X509_num(certs) != 1) {
		status = LIBSSIG_ERROR_ARGUMENT;
	}

	if (status == LIBSSIG_OK) {
		*out_cert = sk_X509_pop(certs);
	}
	sk_X509_pop_free(certs, X509_free);
	return status;
}

bool libssig_ocsp_issuer_valid(X509* cert, X509* issuer) {
	if (X509_check_ca(issuer) <= 0 ||
	    X509_check_issued(issuer, cert) != X509_V_OK) {
		return false;
	}

	EVP_PKEY* key = X509_get_pubkey(issuer);
	bool      ok = key && X509_verify(cert, key) == 1;
	EVP_PKEY_free(key);
	return ok;
}

void libssig_ocsp_request_free(libssig_ocsp_query* query) {
	if (!query) {
		return;
	}
	for (size_t i = 0; i < query->urls.count; ++i) {
		free((void*)query->urls.items[i]);
	}
	free(query->urls.items);
	free(query->data);
	*query = (libssig_ocsp_query){0};
}

static libssig_status url_append(
    const ASN1_IA5STRING* uri,
    libssig_string_list*  urls
) {
	int                  len = ASN1_STRING_length(uri);
	const unsigned char* data = ASN1_STRING_get0_data(uri);
	bool                 http = len > 7 &&
	            OPENSSL_strncasecmp((const char*)data, "http://", 7) == 0;
	bool https = len > 8 &&
	             OPENSSL_strncasecmp((const char*)data, "https://", 8) == 0;
	if (!http && !https) {
		return LIBSSIG_OK;
	}

	if (memchr(data, 0, (size_t)len)) {
		return LIBSSIG_ERROR_FORMAT;
	}

	for (int i = 0; i < len; ++i) {
		if (data[i] <= 0x20 || data[i] >= 0x7f) {
			return LIBSSIG_ERROR_FORMAT;
		}
	}

	if (urls->count >= SIZE_MAX / sizeof(*urls->items)) {
		return LIBSSIG_ERROR_MEMORY;
	}

	char* text = malloc((size_t)len + 1);
	if (!text) {
		return LIBSSIG_ERROR_MEMORY;
	}
	memcpy(text, data, (size_t)len);
	text[len] = '\0';
	const char** items = realloc(
	    urls->items,
	    (urls->count + 1) * sizeof(*items)
	);
	if (!items) {
		free(text);
		return LIBSSIG_ERROR_MEMORY;
	}
	urls->items = items;
	urls->items[urls->count++] = text;
	return LIBSSIG_OK;
}

static libssig_status urls_read(X509* cert, libssig_string_list* urls) {
	int critical = -1;
	AUTHORITY_INFO_ACCESS*
	    aia = X509_get_ext_d2i(cert, NID_info_access, &critical, NULL);
	if (!aia) {
		return critical == -1 ? LIBSSIG_OK : LIBSSIG_ERROR_FORMAT;
	}
	libssig_status status = LIBSSIG_OK;
	for (int i = 0; i < sk_ACCESS_DESCRIPTION_num(aia) && status == LIBSSIG_OK;
	     ++i) {
		ACCESS_DESCRIPTION* item = sk_ACCESS_DESCRIPTION_value(aia, i);
		if (OBJ_obj2nid(item->method) == NID_ad_OCSP &&
		    item->location->type == GEN_URI) {
			status = url_append(
			    item->location->d.uniformResourceIdentifier,
			    urls
			);
		}
	}
	AUTHORITY_INFO_ACCESS_free(aia);
	return status;
}

static libssig_status query_encode(
    X509*               cert,
    X509*               issuer,
    libssig_ocsp_query* query
) {
	OCSP_REQUEST* request = OCSP_REQUEST_new();
	OCSP_CERTID*  id = OCSP_cert_to_id(EVP_sha1(), cert, issuer);
	bool          ok = request && id && OCSP_request_add0_id(request, id);
	if (ok) {
		id = NULL;
	}
	ok = ok && OCSP_request_add1_nonce(request, NULL, 32);
	OCSP_CERTID_free(id);
	int            len = ok ? i2d_OCSP_REQUEST(request, NULL) : -1;
	libssig_status status = LIBSSIG_ERROR_CRYPTO;
	if (len > 0) {
		query->data = malloc((size_t)len);
		if (query->data) {
			unsigned char* cursor = query->data;
			if (i2d_OCSP_REQUEST(request, &cursor) == len) {
				query->len = (size_t)len;
				status = LIBSSIG_OK;
			}
		} else {
			status = LIBSSIG_ERROR_MEMORY;
		}
	}
	OCSP_REQUEST_free(request);
	return status;
}

libssig_status libssig_ocsp_request(
    const libssig_ocsp_request_params* params,
    libssig_ocsp_query*                query
) {
	if (!query) {
		return LIBSSIG_ERROR_ARGUMENT;
	}
	*query = (libssig_ocsp_query){0};
	if (!params ||
	    !libssig_ocsp_buffer_valid(
	        params->cert_data,
	        params->cert_data_len,
	        true
	    ) ||
	    !libssig_ocsp_buffer_valid(
	        params->issuer_data,
	        params->issuer_data_len,
	        true
	    )) {
		return LIBSSIG_ERROR_ARGUMENT;
	}

	X509 *         cert = NULL, *issuer = NULL;
	libssig_status status = libssig_ocsp_certificate(
	    params->cert_data,
	    params->cert_data_len,
	    &cert
	);
	if (status == LIBSSIG_OK) {
		status = libssig_ocsp_certificate(
		    params->issuer_data,
		    params->issuer_data_len,
		    &issuer
		);
	}

	if (status == LIBSSIG_OK && !libssig_ocsp_issuer_valid(cert, issuer)) {
		status = LIBSSIG_ERROR_VERIFY;
	}

	if (status == LIBSSIG_OK) {
		status = urls_read(cert, &query->urls);
	}

	if (status == LIBSSIG_OK) {
		status = query_encode(cert, issuer, query);
	}
	X509_free(cert);
	X509_free(issuer);
	if (status != LIBSSIG_OK) {
		libssig_ocsp_request_free(query);
	}
	return status;
}

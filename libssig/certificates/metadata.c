/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "internal.h"
#include <limits.h>
#include <openssl/x509v3.h>
#include <stdint.h>
#include <stdlib.h>

static void oid_list_clear(libssig_string_list* list) {
	for (size_t i = 0; i < list->count; ++i) {
		free((void*)list->items[i]);
	}
	free(list->items);
	*list = (libssig_string_list){0};
}

void libssig_certificate_metadata_clear(libssig_certificate* cert) {
	free(cert->key_usage_names.items);
	cert->key_usage_names = (libssig_string_list){0};
	oid_list_clear(&cert->extended_key_usage);
	oid_list_clear(&cert->certificate_policies);
	cert->metadata_status = LIBSSIG_CERTIFICATE_METADATA_UNAVAILABLE;
	cert->key_usage_present = false;
	cert->key_usage = 0;
	cert->extended_key_usage_present = false;
	cert->certificate_policies_present = false;
}

static libssig_status oid_append(
    libssig_string_list* list,
    const ASN1_OBJECT*   object
) {
	int len = OBJ_obj2txt(NULL, 0, object, 1);
	if (len <= 0 || len == INT_MAX) {
		return LIBSSIG_ERROR_ARGUMENT;
	}

	if (list->count >= SIZE_MAX / sizeof(*list->items)) {
		return LIBSSIG_ERROR_MEMORY;
	}

	char* text = malloc((size_t)len + 1);
	if (!text) {
		return LIBSSIG_ERROR_MEMORY;
	}

	if (OBJ_obj2txt(text, len + 1, object, 1) != len) {
		free(text);
		return LIBSSIG_ERROR_ARGUMENT;
	}

	const char** items = realloc(
	    list->items,
	    (list->count + 1) * sizeof(*items)
	);
	if (!items) {
		free(text);
		return LIBSSIG_ERROR_MEMORY;
	}
	list->items = items;
	list->items[list->count++] = text;
	return LIBSSIG_OK;
}

static libssig_status key_usage_names_read(libssig_certificate* cert) {
	static const char* names[] = {
	    "digital-signature",
	    "content-commitment",
	    "key-encipherment",
	    "data-encipherment",
	    "key-agreement",
	    "key-cert-sign",
	    "crl-sign",
	    "encipher-only",
	    "decipher-only",
	};
	size_t count = 0;
	for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
		if (cert->key_usage & (1u << i)) {
			++count;
		}
	}

	if (!count) {
		return LIBSSIG_OK;
	}

	cert->key_usage_names.items = malloc(
	    count * sizeof(*cert->key_usage_names.items)
	);
	if (!cert->key_usage_names.items) {
		return LIBSSIG_ERROR_MEMORY;
	}

	for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
		if (cert->key_usage & (1u << i)) {
			cert->key_usage_names
			    .items[cert->key_usage_names.count++] = names[i];
		}
	}
	return LIBSSIG_OK;
}

static libssig_status key_usage_read(X509* x509, libssig_certificate* cert) {
	int critical = -1;
	ASN1_BIT_STRING*
	    usage = X509_get_ext_d2i(x509, NID_key_usage, &critical, NULL);
	if (!usage) {
		return critical == -1 ? LIBSSIG_OK : LIBSSIG_ERROR_ARGUMENT;
	}

	cert->key_usage_present = true;
	for (int i = 0; i < 9; ++i) {
		if (ASN1_BIT_STRING_get_bit(usage, i)) {
			cert->key_usage |= 1u << i;
		}
	}
	ASN1_BIT_STRING_free(usage);
	return key_usage_names_read(cert);
}

static libssig_status extended_key_usage_read(
    X509*                x509,
    libssig_certificate* cert
) {
	int critical = -1;
	EXTENDED_KEY_USAGE*
	    usage = X509_get_ext_d2i(x509, NID_ext_key_usage, &critical, NULL);
	if (!usage) {
		return critical == -1 ? LIBSSIG_OK : LIBSSIG_ERROR_ARGUMENT;
	}

	cert->extended_key_usage_present = true;
	libssig_status status = LIBSSIG_OK;
	for (int i = 0; i < sk_ASN1_OBJECT_num(usage); ++i) {
		status = oid_append(
		    &cert->extended_key_usage,
		    sk_ASN1_OBJECT_value(usage, i)
		);
		if (status != LIBSSIG_OK) {
			break;
		}
	}
	EXTENDED_KEY_USAGE_free(usage);
	return status;
}

static libssig_status certificate_policies_read(
    X509*                x509,
    libssig_certificate* cert
) {
	int                  critical = -1;
	CERTIFICATEPOLICIES* policies = X509_get_ext_d2i(
	    x509,
	    NID_certificate_policies,
	    &critical,
	    NULL
	);
	if (!policies) {
		return critical == -1 ? LIBSSIG_OK : LIBSSIG_ERROR_ARGUMENT;
	}

	cert->certificate_policies_present = true;
	libssig_status status = LIBSSIG_OK;
	for (int i = 0; i < sk_POLICYINFO_num(policies); ++i) {
		const POLICYINFO* policy = sk_POLICYINFO_value(policies, i);
		status = oid_append(&cert->certificate_policies, policy->policyid);
		if (status != LIBSSIG_OK) {
			break;
		}
	}
	CERTIFICATEPOLICIES_free(policies);
	return status;
}

static libssig_status extensions_read(X509* x509, libssig_certificate* cert) {
	libssig_status status = key_usage_read(x509, cert);
	if (status == LIBSSIG_OK) {
		status = extended_key_usage_read(x509, cert);
	}

	if (status == LIBSSIG_OK) {
		status = certificate_policies_read(x509, cert);
	}
	return status;
}

libssig_status libssig_certificate_metadata_read(libssig_certificate* cert) {
	if (!cert->der) {
		return LIBSSIG_OK;
	}

	cert->metadata_status = LIBSSIG_CERTIFICATE_METADATA_INVALID;
	if (!cert->der_len || cert->der_len > LONG_MAX) {
		return LIBSSIG_OK;
	}

	const unsigned char* cursor = cert->der;
	X509*                x509 = d2i_X509(NULL, &cursor, (long)cert->der_len);
	if (!x509 || cursor != cert->der + cert->der_len) {
		X509_free(x509);
		return LIBSSIG_OK;
	}

	libssig_status status = extensions_read(x509, cert);
	X509_free(x509);
	if (status != LIBSSIG_OK) {
		libssig_certificate_metadata_clear(cert);
		cert->metadata_status = LIBSSIG_CERTIFICATE_METADATA_INVALID;
		return status == LIBSSIG_ERROR_MEMORY ? status : LIBSSIG_OK;
	}
	cert->metadata_status = LIBSSIG_CERTIFICATE_METADATA_VALID;
	return LIBSSIG_OK;
}

/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <libssig/internal.h>
#include <stdint.h>
#include <stdlib.h>

static void certificate_free(libssig_certificate* cert) {
	free(cert->id);
	free(cert->label);
	free(cert->der);
	*cert = (libssig_certificate){0};
}

void libssig_certificates_free(libssig_certificates* certs) {
	if (!certs) {
		return;
	}
	for (size_t i = 0; i < certs->count; ++i) {
		certificate_free(&certs->items[i]);
	}
	free(certs->items);
	certs->items = NULL;
	certs->count = 0;
	certs->ck_rv = 0;
}

static bool attribute_unavailable(CK_RV rv) {
	return rv == CKR_ATTRIBUTE_SENSITIVE || rv == CKR_ATTRIBUTE_TYPE_INVALID;
}

static libssig_status read_attribute(
    pkcs11_session*   s,
    CK_OBJECT_HANDLE  object,
    CK_ATTRIBUTE_TYPE type,
    unsigned char**   data,
    size_t*           length,
    CK_RV*            out_rv
) {
	*data = NULL;
	*length = 0;
	CK_ATTRIBUTE attribute = {type, NULL, 0};
	*out_rv = s->module->C_GetAttributeValue(s->handle, object, &attribute, 1);
	if (attribute_unavailable(*out_rv)) {
		*out_rv = CKR_OK;
		return LIBSSIG_OK;
	}
	if (*out_rv != CKR_OK) {
		return LIBSSIG_ERROR_PKCS11;
	}
	if (attribute.ulValueLen == CK_UNAVAILABLE_INFORMATION) {
		return LIBSSIG_OK;
	}
	if (attribute.ulValueLen >= SIZE_MAX) {
		return LIBSSIG_ERROR_MEMORY;
	}
	size_t         capacity = (size_t)attribute.ulValueLen;
	unsigned char* buffer = calloc(capacity + 1, 1);
	if (!buffer) {
		return LIBSSIG_ERROR_MEMORY;
	}
	attribute.pValue = buffer;
	*out_rv = s->module->C_GetAttributeValue(s->handle, object, &attribute, 1);
	if (attribute_unavailable(*out_rv)) {
		free(buffer);
		*out_rv = CKR_OK;
		return LIBSSIG_OK;
	}
	if (*out_rv != CKR_OK) {
		free(buffer);
		return LIBSSIG_ERROR_PKCS11;
	}
	if (attribute.ulValueLen == CK_UNAVAILABLE_INFORMATION) {
		free(buffer);
		return LIBSSIG_OK;
	}
	if (attribute.ulValueLen > capacity) {
		free(buffer);
		*out_rv = CKR_BUFFER_TOO_SMALL;
		return LIBSSIG_ERROR_PKCS11;
	}
	buffer[attribute.ulValueLen] = 0;
	*data = buffer;
	*length = (size_t)attribute.ulValueLen;
	return LIBSSIG_OK;
}

static libssig_status read_certificate(
    pkcs11_session*      s,
    CK_OBJECT_HANDLE     object,
    libssig_certificate* cert,
    CK_RV*               out_rv
) {
	libssig_status status =
	    read_attribute(s, object, CKA_ID, &cert->id, &cert->id_len, out_rv);
	if (status != LIBSSIG_OK) {
		return status;
	}
	unsigned char* label = NULL;
	status =
	    read_attribute(s, object, CKA_LABEL, &label, &cert->label_len, out_rv);
	cert->label = (char*)label;
	if (status != LIBSSIG_OK) {
		return status;
	}
	return read_attribute(
	    s,
	    object,
	    CKA_VALUE,
	    &cert->der,
	    &cert->der_len,
	    out_rv
	);
}

static libssig_status append_certificate(
    pkcs11_session*       s,
    CK_OBJECT_HANDLE      object,
    libssig_certificates* certs,
    CK_RV*                out_rv
) {
	libssig_certificate cert = {0};
	libssig_status      status = read_certificate(s, object, &cert, out_rv);
	if (status != LIBSSIG_OK) {
		certificate_free(&cert);
		return status;
	}
	if (certs->count >= SIZE_MAX / sizeof(*certs->items)) {
		certificate_free(&cert);
		return LIBSSIG_ERROR_MEMORY;
	}
	libssig_certificate* entries =
	    realloc(certs->items, (certs->count + 1) * sizeof(*entries));
	if (!entries) {
		certificate_free(&cert);
		return LIBSSIG_ERROR_MEMORY;
	}
	certs->items = entries;
	certs->items[certs->count++] = cert;
	return LIBSSIG_OK;
}

libssig_status pkcs11_collect_certificates(
    pkcs11_session*       s,
    libssig_certificates* certs,
    CK_RV*                out_rv
) {
	CK_OBJECT_CLASS     object_class = CKO_CERTIFICATE;
	CK_CERTIFICATE_TYPE type = CKC_X_509;
	CK_ATTRIBUTE        attributes[] = {
        {CKA_CLASS, &object_class, sizeof(object_class)},
        {CKA_CERTIFICATE_TYPE, &type, sizeof(type)}
    };
	*out_rv = s->module->C_FindObjectsInit(s->handle, attributes, 2);
	if (*out_rv != CKR_OK) {
		return LIBSSIG_ERROR_PKCS11;
	}
	libssig_status status = LIBSSIG_OK;
	for (;;) {
		CK_OBJECT_HANDLE object;
		CK_ULONG         count = 0;
		*out_rv = s->module->C_FindObjects(s->handle, &object, 1, &count);
		if (*out_rv != CKR_OK) {
			status = LIBSSIG_ERROR_PKCS11;
			break;
		}
		if (!count) {
			break;
		}
		status = append_certificate(s, object, certs, out_rv);
		if (status != LIBSSIG_OK) {
			break;
		}
	}
	CK_RV final_rv = s->module->C_FindObjectsFinal(s->handle);
	if (status == LIBSSIG_OK && final_rv != CKR_OK) {
		*out_rv = final_rv;
		status = LIBSSIG_ERROR_PKCS11;
	}
	if (status != LIBSSIG_OK) {
		libssig_certificates_free(certs);
		return status;
	}

	return LIBSSIG_OK;
}

libssig_status libssig_list_certificates(
    const libssig_token*  token,
    libssig_certificates* certs
) {
	if (!certs) {
		return LIBSSIG_ERROR_ARGUMENT;
	}
	*certs = (libssig_certificates){0};
	if (!token || !token->uri) {
		return LIBSSIG_ERROR_ARGUMENT;
	}
	pkcs11_context ctx = {0};
	libssig_status status = pkcs11_context_open(&ctx);
	if (status != LIBSSIG_OK) {
		return status;
	}
	pkcs11_session s = {0};
	CK_RV          rv = CKR_OK;
	status = pkcs11_session_open(&ctx, token->uri, &s, &rv);
	if (status == LIBSSIG_OK) {
		status = pkcs11_collect_certificates(&s, certs, &rv);
	}
	CK_RV close_rv = pkcs11_session_close(&s);
	pkcs11_context_close(&ctx);
	if (status == LIBSSIG_OK && close_rv != CKR_OK) {
		rv = close_rv;
		status = LIBSSIG_ERROR_PKCS11;
	}
	if (status != LIBSSIG_OK) {
		libssig_certificates_free(certs);
	}
	certs->ck_rv = rv;
	return status;
}

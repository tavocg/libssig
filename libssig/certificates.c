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

void libssig_certificates_free(libssig_certificate_list* certs) {
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

static bool attribute_is_unavailable(CK_RV rv) {
	return rv == CKR_ATTRIBUTE_SENSITIVE || rv == CKR_ATTRIBUTE_TYPE_INVALID;
}

static libssig_status attribute_read(
    libssig_session*  s,
    CK_OBJECT_HANDLE  object,
    CK_ATTRIBUTE_TYPE type,
    unsigned char**   out_data,
    size_t*           out_len,
    CK_RV*            out_rv
) {
	*out_data = NULL;
	*out_len = 0;
	CK_ATTRIBUTE attribute = {type, NULL, 0};
	*out_rv = s->module->C_GetAttributeValue(s->handle, object, &attribute, 1);

	if (attribute_is_unavailable(*out_rv)) {
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
	if (attribute_is_unavailable(*out_rv)) {
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
	*out_data = buffer;
	*out_len = (size_t)attribute.ulValueLen;
	return LIBSSIG_OK;
}

static libssig_status certificate_read(
    libssig_session*     s,
    CK_OBJECT_HANDLE     object,
    libssig_certificate* cert,
    CK_RV*               out_rv
) {
	libssig_status status = attribute_read(
	    s,
	    object,
	    CKA_ID,
	    &cert->id,
	    &cert->id_len,
	    out_rv
	);

	if (status != LIBSSIG_OK) {
		return status;
	}

	unsigned char* label = NULL;
	status = attribute_read(
	    s,
	    object,
	    CKA_LABEL,
	    &label,
	    &cert->label_len,
	    out_rv
	);

	cert->label = (char*)label;

	if (status != LIBSSIG_OK) {
		return status;
	}

	return attribute_read(
	    s,
	    object,
	    CKA_VALUE,
	    &cert->der,
	    &cert->der_len,
	    out_rv
	);
}

static libssig_status certificates_collect_one(
    libssig_session*          s,
    CK_OBJECT_HANDLE          object,
    libssig_certificate_list* certs,
    CK_RV*                    out_rv
) {
	libssig_certificate cert = {0};
	libssig_status      status = certificate_read(s, object, &cert, out_rv);
	if (status != LIBSSIG_OK) {
		certificate_free(&cert);
		return status;
	}

	if (certs->count >= SIZE_MAX / sizeof(*certs->items)) {
		certificate_free(&cert);
		return LIBSSIG_ERROR_MEMORY;
	}

	libssig_certificate* items = realloc(
	    certs->items,
	    (certs->count + 1) * sizeof(*items)
	);

	if (!items) {
		certificate_free(&cert);
		return LIBSSIG_ERROR_MEMORY;
	}

	certs->items = items;
	certs->items[certs->count++] = cert;

	return LIBSSIG_OK;
}

libssig_status libssig_certificates_collect(
    libssig_session*          s,
    libssig_certificate_list* certs,
    CK_RV*                    out_rv
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
		status = certificates_collect_one(s, object, certs, out_rv);
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

libssig_status libssig_certificates(
    const libssig_context*    ctx,
    const libssig_token*      token,
    libssig_certificate_list* certs
) {
	if (!certs) {
		return LIBSSIG_ERROR_ARGUMENT;
	}

	*certs = (libssig_certificate_list){0};
	if (!ctx || !ctx->impl || !ctx->impl->modules || !token || !token->uri) {
		return LIBSSIG_ERROR_ARGUMENT;
	}

	libssig_session s = {0};
	CK_RV           rv = CKR_OK;
	libssig_status  status = libssig_session_open(ctx, token->uri, &s, &rv);
	if (status == LIBSSIG_OK) {
		status = libssig_certificates_collect(&s, certs, &rv);
	}

	CK_RV close_rv = libssig_session_close(&s);
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

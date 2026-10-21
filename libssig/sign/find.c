/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "internal.h"
#include <limits.h>

static libssig_status key_unique_find(
    libssig_session*  s,
    CK_OBJECT_HANDLE* out_key,
    CK_RV*            out_rv
) {
	CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
	for (;;) {
		CK_OBJECT_HANDLE object = CK_INVALID_HANDLE;
		CK_ULONG         count = 0;
		*out_rv = s->module->C_FindObjects(s->handle, &object, 1, &count);
		if (*out_rv != CKR_OK) {
			return LIBSSIG_ERROR_PKCS11;
		}

		if (!count) {
			break;
		}

		if (key != CK_INVALID_HANDLE) {
			return LIBSSIG_ERROR_AMBIGUOUS;
		}
		key = object;
	}

	if (key == CK_INVALID_HANDLE) {
		return LIBSSIG_ERROR_NOT_FOUND;
	}

	*out_key = key;
	return LIBSSIG_OK;
}

static libssig_status key_capabilities_check(
    libssig_session* s,
    CK_OBJECT_HANDLE key,
    CK_KEY_TYPE      expected_type,
    CK_RV*           out_rv
) {
	CK_KEY_TYPE  key_type = 0;
	CK_BBOOL     can_sign = CK_FALSE;
	CK_ATTRIBUTE capabilities[] = {
	    {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
	    {CKA_SIGN, &can_sign, sizeof(can_sign)},
	};
	*out_rv = s->module->C_GetAttributeValue(s->handle, key, capabilities, 2);
	if (*out_rv != CKR_OK) {
		return LIBSSIG_ERROR_PKCS11;
	}

	if (capabilities[0].ulValueLen != sizeof(key_type) ||
	    capabilities[1].ulValueLen != sizeof(can_sign) ||
	    key_type != expected_type || can_sign != CK_TRUE) {
		return LIBSSIG_ERROR_UNSUPPORTED;
	}

	return LIBSSIG_OK;
}

libssig_status libssig_private_key_find(
    libssig_session*     s,
    const unsigned char* id,
    size_t               id_len,
    CK_KEY_TYPE          expected_type,
    CK_OBJECT_HANDLE*    out_key,
    CK_RV*               out_rv
) {
	if (!out_key || !out_rv) {
		return LIBSSIG_ERROR_ARGUMENT;
	}

	*out_key = CK_INVALID_HANDLE;
	*out_rv = CKR_OK;
	if (!s || !s->open || !s->module || !id || !id_len || id_len > ULONG_MAX) {
		return LIBSSIG_ERROR_ARGUMENT;
	}

	CK_OBJECT_CLASS object_class = CKO_PRIVATE_KEY;
	CK_ATTRIBUTE    attributes[] = {
        {CKA_CLASS, &object_class, sizeof(object_class)},
        {CKA_ID, (void*)id, (CK_ULONG)id_len},
    };
	*out_rv = s->module->C_FindObjectsInit(s->handle, attributes, 2);
	if (*out_rv != CKR_OK) {
		return LIBSSIG_ERROR_PKCS11;
	}

	CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
	libssig_status   status = key_unique_find(s, &key, out_rv);
	CK_RV            final_rv = s->module->C_FindObjectsFinal(s->handle);
	if (status == LIBSSIG_OK && final_rv != CKR_OK) {
		*out_rv = final_rv;
		status = LIBSSIG_ERROR_PKCS11;
	}

	if (status == LIBSSIG_OK) {
		status = key_capabilities_check(s, key, expected_type, out_rv);
	}

	if (status == LIBSSIG_OK) {
		*out_key = key;
	}
	return status;
}

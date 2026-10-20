/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <libssig/internal.h>
#include <stdio.h>
#include <string.h>

#define CHECK(expr)                                                            \
	do {                                                                       \
		if (!(expr)) {                                                         \
			fprintf(stderr, "Failed at %d: %s\n", __LINE__, #expr);            \
			return 1;                                                          \
		}                                                                      \
	} while (0)

static unsigned int cursor;
static unsigned int finalize_count;
static unsigned int object_count = 2;
static CK_RV        find_rv = CKR_OK;
static CK_RV        attribute_rv = CKR_OK;
static CK_RV        final_rv = CKR_OK;
static bool         attribute_missing;
static bool         attribute_grows;

static CK_RV mock_objects_find_init(
    CK_SESSION_HANDLE handle,
    CK_ATTRIBUTE_PTR  attributes,
    CK_ULONG          count
) {
	(void)handle;
	cursor = 0;
	if (count != 2 || attributes[0].type != CKA_CLASS ||
	    *(CK_OBJECT_CLASS*)attributes[0].pValue != CKO_CERTIFICATE ||
	    *(CK_CERTIFICATE_TYPE*)attributes[1].pValue != CKC_X_509) {
		return CKR_ARGUMENTS_BAD;
	}
	return CKR_OK;
}

static CK_RV mock_objects_find(
    CK_SESSION_HANDLE    handle,
    CK_OBJECT_HANDLE_PTR object,
    CK_ULONG             capacity,
    CK_ULONG_PTR         count
) {
	(void)handle;
	(void)capacity;
	*count = cursor < object_count ? 1 : 0;
	*object = ++cursor;
	return find_rv;
}

static CK_RV mock_objects_find_final(CK_SESSION_HANDLE handle) {
	(void)handle;
	++finalize_count;
	return final_rv;
}

static CK_RV mock_attribute_get(
    CK_SESSION_HANDLE handle,
    CK_OBJECT_HANDLE  object,
    CK_ATTRIBUTE_PTR  attribute,
    CK_ULONG          count
) {
	(void)handle;
	(void)object;
	(void)count;
	static const unsigned char id[] = {0, 0xff, 1};
	static const unsigned char der[] = {0x30, 0x02, 0x05, 0};
	const void*                value = id;
	CK_ULONG                   len = sizeof(id);
	if (attribute_rv != CKR_OK) {
		return attribute_rv;
	}
	if (attribute_missing) {
		attribute->ulValueLen = CK_UNAVAILABLE_INFORMATION;
		return CKR_ATTRIBUTE_TYPE_INVALID;
	}
	if (attribute->type == CKA_LABEL) {
		value = "test";
		len = 4;
	}
	if (attribute->type == CKA_VALUE) {
		value = der;
		len = sizeof(der);
	}
	if (attribute->pValue && attribute_grows) {
		attribute->ulValueLen = len + 1;
		return CKR_BUFFER_TOO_SMALL;
	}
	if (attribute->pValue) {
		memcpy(attribute->pValue, value, len);
	}
	attribute->ulValueLen = len;
	return CKR_OK;
}

int main(void) {
	CK_FUNCTION_LIST module = {0};
	module.C_FindObjectsInit = mock_objects_find_init;
	module.C_FindObjects = mock_objects_find;
	module.C_FindObjectsFinal = mock_objects_find_final;
	module.C_GetAttributeValue = mock_attribute_get;
	libssig_session      s = {.module = &module, .open = true};
	libssig_certificates certs = {0};
	CK_RV                rv = CKR_OK;
	CHECK(libssig_certificates_collect(&s, &certs, &rv) == LIBSSIG_OK);
	CHECK(finalize_count == 1 && certs.count == 2);
	CHECK(certs.items[0].id_len == 3 && certs.items[0].id[1] == 0xff);
	CHECK(!strcmp(certs.items[1].label, "test"));
	CHECK(certs.items[0].der_len == 4);
	libssig_certificates_free(&certs);
	libssig_certificates_free(&certs);
	object_count = 0;
	CHECK(libssig_certificates_collect(&s, &certs, &rv) == LIBSSIG_OK);
	CHECK(certs.count == 0);
	object_count = 1;
	attribute_missing = true;
	CHECK(libssig_certificates_collect(&s, &certs, &rv) == LIBSSIG_OK);
	CHECK(certs.items[0].der == NULL && rv == CKR_OK);
	libssig_certificates_free(&certs);
	attribute_missing = false;
	attribute_rv = CKR_DEVICE_ERROR;
	CHECK(
	    libssig_certificates_collect(&s, &certs, &rv) == LIBSSIG_ERROR_PKCS11
	);
	CHECK(rv == CKR_DEVICE_ERROR && !certs.items);
	attribute_rv = CKR_OK;
	attribute_grows = true;
	CHECK(
	    libssig_certificates_collect(&s, &certs, &rv) == LIBSSIG_ERROR_PKCS11
	);
	CHECK(rv == CKR_BUFFER_TOO_SMALL);
	attribute_grows = false;
	find_rv = CKR_DEVICE_REMOVED;
	CHECK(
	    libssig_certificates_collect(&s, &certs, &rv) == LIBSSIG_ERROR_PKCS11
	);
	CHECK(rv == CKR_DEVICE_REMOVED);
	find_rv = CKR_OK;
	final_rv = CKR_GENERAL_ERROR;
	CHECK(
	    libssig_certificates_collect(&s, &certs, &rv) == LIBSSIG_ERROR_PKCS11
	);
	CHECK(rv == CKR_GENERAL_ERROR && !certs.items);
	CHECK(finalize_count == 7);
	CHECK(libssig_certificates_list(NULL, &certs) == LIBSSIG_ERROR_ARGUMENT);
	libssig_token token = {0};
	CHECK(libssig_certificates_list(&token, &certs) == LIBSSIG_ERROR_ARGUMENT);
	CHECK(libssig_certificates_list(&token, NULL) == LIBSSIG_ERROR_ARGUMENT);
	libssig_certificates_free(NULL);
	return 0;
}

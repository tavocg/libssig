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
static unsigned int finals;
static unsigned int objects = 2;
static CK_RV        find_rv = CKR_OK;
static CK_RV        attribute_rv = CKR_OK;
static CK_RV        final_rv = CKR_OK;
static bool         missing;
static bool         grow;

static CK_RV init(
    CK_SESSION_HANDLE handle,
    CK_ATTRIBUTE_PTR  attrs,
    CK_ULONG          count
) {
	(void)handle;
	cursor = 0;
	if (count != 2 || attrs[0].type != CKA_CLASS ||
	    *(CK_OBJECT_CLASS*)attrs[0].pValue != CKO_CERTIFICATE ||
	    *(CK_CERTIFICATE_TYPE*)attrs[1].pValue != CKC_X_509) {
		return CKR_ARGUMENTS_BAD;
	}
	return CKR_OK;
}

static CK_RV find(
    CK_SESSION_HANDLE    handle,
    CK_OBJECT_HANDLE_PTR object,
    CK_ULONG             capacity,
    CK_ULONG_PTR         count
) {
	(void)handle;
	(void)capacity;
	*count = cursor < objects ? 1 : 0;
	*object = ++cursor;
	return find_rv;
}

static CK_RV final(CK_SESSION_HANDLE handle) {
	(void)handle;
	++finals;
	return final_rv;
}

static CK_RV attribute(
    CK_SESSION_HANDLE handle,
    CK_OBJECT_HANDLE  object,
    CK_ATTRIBUTE_PTR  attr,
    CK_ULONG          count
) {
	(void)handle;
	(void)object;
	(void)count;
	static const unsigned char id[] = {0, 0xff, 1};
	static const unsigned char der[] = {0x30, 0x02, 0x05, 0};
	const void*                value = id;
	CK_ULONG                   length = sizeof(id);
	if (attribute_rv != CKR_OK) {
		return attribute_rv;
	}
	if (missing) {
		attr->ulValueLen = CK_UNAVAILABLE_INFORMATION;
		return CKR_ATTRIBUTE_TYPE_INVALID;
	}
	if (attr->type == CKA_LABEL) {
		value = "test";
		length = 4;
	}
	if (attr->type == CKA_VALUE) {
		value = der;
		length = sizeof(der);
	}
	if (attr->pValue && grow) {
		attr->ulValueLen = length + 1;
		return CKR_BUFFER_TOO_SMALL;
	}
	if (attr->pValue) {
		memcpy(attr->pValue, value, length);
	}
	attr->ulValueLen = length;
	return CKR_OK;
}

int main(void) {
	CK_FUNCTION_LIST module = {0};
	module.C_FindObjectsInit = init;
	module.C_FindObjects = find;
	module.C_FindObjectsFinal = final;
	module.C_GetAttributeValue = attribute;
	pkcs11_session       s = {.module = &module, .open = true};
	libssig_certificates certs = {0};
	CK_RV                rv = CKR_OK;
	CHECK(pkcs11_collect_certificates(&s, &certs, &rv) == LIBSSIG_OK);
	CHECK(finals == 1 && certs.count == 2);
	CHECK(certs.items[0].id_len == 3 && certs.items[0].id[1] == 0xff);
	CHECK(!strcmp(certs.items[1].label, "test"));
	CHECK(certs.items[0].der_len == 4);
	libssig_certificates_free(&certs);
	libssig_certificates_free(&certs);
	objects = 0;
	CHECK(pkcs11_collect_certificates(&s, &certs, &rv) == LIBSSIG_OK);
	CHECK(certs.count == 0);
	objects = 1;
	missing = true;
	CHECK(pkcs11_collect_certificates(&s, &certs, &rv) == LIBSSIG_OK);
	CHECK(certs.items[0].der == NULL && rv == CKR_OK);
	libssig_certificates_free(&certs);
	missing = false;
	attribute_rv = CKR_DEVICE_ERROR;
	CHECK(pkcs11_collect_certificates(&s, &certs, &rv) == LIBSSIG_ERROR_PKCS11);
	CHECK(rv == CKR_DEVICE_ERROR && !certs.items);
	attribute_rv = CKR_OK;
	grow = true;
	CHECK(pkcs11_collect_certificates(&s, &certs, &rv) == LIBSSIG_ERROR_PKCS11);
	CHECK(rv == CKR_BUFFER_TOO_SMALL);
	grow = false;
	find_rv = CKR_DEVICE_REMOVED;
	CHECK(pkcs11_collect_certificates(&s, &certs, &rv) == LIBSSIG_ERROR_PKCS11);
	CHECK(rv == CKR_DEVICE_REMOVED);
	find_rv = CKR_OK;
	final_rv = CKR_GENERAL_ERROR;
	CHECK(pkcs11_collect_certificates(&s, &certs, &rv) == LIBSSIG_ERROR_PKCS11);
	CHECK(rv == CKR_GENERAL_ERROR && !certs.items);
	CHECK(finals == 7);
	CHECK(libssig_list_certificates(NULL, &certs) == LIBSSIG_ERROR_ARGUMENT);
	libssig_token token = {0};
	CHECK(libssig_list_certificates(&token, &certs) == LIBSSIG_ERROR_ARGUMENT);
	CHECK(libssig_list_certificates(&token, NULL) == LIBSSIG_ERROR_ARGUMENT);
	libssig_certificates_free(NULL);
	return 0;
}

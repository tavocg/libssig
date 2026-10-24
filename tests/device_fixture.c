/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Loadable, PIN-free fixture shared by the library and consuming GUI tests. */
#define CRYPTOKI_EXPORTS 1
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <p11-kit/pkcs11.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned char*  der;
static size_t          der_len;
static CK_OBJECT_CLASS selected;
static CK_ULONG        found;
static char            phase(void) {
    const char* path = getenv("LIBSSIG_DEVICE_PHASE");
    FILE*       file = path ? fopen(path, "r") : NULL;
    int         value = file ? fgetc(file) : '0';
    if (file) {
        fclose(file);
    }
    return (char)value;
}
static void trace(const char* event) {
	const char* path = getenv("LIBSSIG_DEVICE_LOG");
	FILE*       file = path ? fopen(path, "a") : NULL;
	if (file) {
		fprintf(file, "%s\n", event);
		fclose(file);
	}
}
static void padded(unsigned char* out, size_t size, const char* value) {
	memset(out, ' ', size);
	size_t length = strlen(value);
	memcpy(out, value, length < size ? length : size);
}
static CK_RV initialize(CK_VOID_PTR args) {
	(void)args;
	trace("initialize");
	const char* path = getenv("LIBSSIG_DEVICE_CERT");
	FILE*       file = path ? fopen(path, "rb") : NULL;
	if (file) {
		if (fseek(file, 0, SEEK_END) != 0) {
			fclose(file);
			return CKR_GENERAL_ERROR;
		}
		long size = ftell(file);
		if (size <= 0 || size > 1024 * 1024 || fseek(file, 0, SEEK_SET) != 0) {
			fclose(file);
			return CKR_GENERAL_ERROR;
		}
		der = OPENSSL_malloc((size_t)size);
		der_len = (size_t)size;
		bool ok = der && fread(der, 1, der_len, file) == der_len;
		fclose(file);
		return ok ? CKR_OK : CKR_GENERAL_ERROR;
	}
	EVP_PKEY* key = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", 2048);
	X509*     cert = X509_new();
	bool      ok = key && cert && X509_set_version(cert, 2) &&
	          ASN1_INTEGER_set(X509_get_serialNumber(cert), 1) &&
	          X509_set_pubkey(cert, key) &&
	          X509_gmtime_adj(X509_getm_notBefore(cert), -60) &&
	          X509_gmtime_adj(X509_getm_notAfter(cert), 86400) &&
	          X509_NAME_add_entry_by_txt(
	              X509_get_subject_name(cert),
	              "CN",
	              MBSTRING_ASC,
	              (const unsigned char*)"Device fixture & signer",
	              -1,
	              -1,
	              0
	          ) &&
	          X509_set_issuer_name(cert, X509_get_subject_name(cert)) &&
	          X509_sign(cert, key, EVP_sha256());
	int length = ok ? i2d_X509(cert, &der) : -1;
	der_len = length > 0 ? (size_t)length : 0;
	X509_free(cert);
	EVP_PKEY_free(key);
	return der_len ? CKR_OK : CKR_GENERAL_ERROR;
}
static CK_RV finalize(CK_VOID_PTR args) {
	(void)args;
	trace("finalize");
	OPENSSL_free(der);
	der = NULL;
	der_len = 0;
	return CKR_OK;
}
static CK_RV info(CK_INFO_PTR out) {
	memset(out, 0, sizeof(*out));
	out->cryptokiVersion = (CK_VERSION){2, 40};
	out->libraryVersion = (CK_VERSION){1, 5};
	padded(out->manufacturerID, sizeof(out->manufacturerID), "CRSign tests");
	padded(
	    out->libraryDescription,
	    sizeof(out->libraryDescription),
	    "Device fixture"
	);
	return CKR_OK;
}
static CK_RV slots(CK_BBOOL present, CK_SLOT_ID_PTR out, CK_ULONG_PTR count) {
	(void)present;
	CK_ULONG size = phase() == '3' ? 1 : 4;
	if (out) {
		if (*count < size) {
			*count = size;
			return CKR_BUFFER_TOO_SMALL;
		}
		for (CK_ULONG n = 0; n < size; ++n) {
			out[n] = size == 1 ? 4 : n + 1;
		}
	}
	*count = size;
	return CKR_OK;
}
static CK_RV slot_info(CK_SLOT_ID id, CK_SLOT_INFO_PTR out) {
	if (id == 1 && phase() == '6') {
		return CKR_DEVICE_ERROR;
	}
	memset(out, 0, sizeof(*out));
	out->flags = id == 4 ? 0 : CKF_HW_SLOT | CKF_REMOVABLE_DEVICE;
	if (id != 2 && !(id == 1 && phase() == '1')) {
		out->flags |= CKF_TOKEN_PRESENT;
	}
	padded(
	    out->slotDescription,
	    sizeof(out->slotDescription),
	    id <= 2   ? "USB fixture <&>"
	    : id == 3 ? "Failing reader"
	              : "Software fixture"
	);
	padded(
	    out->manufacturerID,
	    sizeof(out->manufacturerID),
	    "Test reader maker"
	);
	return CKR_OK;
}
static CK_RV token_info(CK_SLOT_ID id, CK_TOKEN_INFO_PTR out) {
	trace("token-info");
	char current = phase();
	if (id == 1 && current == '1') {
		return CKR_TOKEN_NOT_PRESENT;
	}
	if (id == 1 && current == '5') {
		return CKR_DEVICE_ERROR;
	}
	memset(out, 0, sizeof(*out));
	padded(
	    out->label,
	    sizeof(out->label),
	    id == 4 ? "Software certificate store" : "Signing card <&>"
	);
	padded(
	    out->manufacturerID,
	    sizeof(out->manufacturerID),
	    "Test token maker"
	);
	padded(out->model, sizeof(out->model), "Fixture");
	padded(
	    out->serialNumber,
	    sizeof(out->serialNumber),
	    current == '2' ? "card-two" : "card-one"
	);
	out->flags = current == '4' ? CKF_TOKEN_INITIALIZED | CKF_LOGIN_REQUIRED |
	                                  CKF_USER_PIN_COUNT_LOW
	                            : CKF_TOKEN_INITIALIZED | CKF_LOGIN_REQUIRED |
	                                  CKF_USER_PIN_FINAL_TRY;
	out->ulMinPinLen = 4;
	out->ulMaxPinLen = 12;
	out->ulTotalPublicMemory = 8192;
	out->ulFreePublicMemory = 4096;
	out->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
	out->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
	return CKR_OK;
}
static CK_RV open_session(
    CK_SLOT_ID            id,
    CK_FLAGS              flags,
    CK_VOID_PTR           app,
    CK_NOTIFY             notify,
    CK_SESSION_HANDLE_PTR out
) {
	(void)app;
	(void)notify;
	if (flags != CKF_SERIAL_SESSION) {
		abort();
	}
	if (id == 3) {
		return CKR_DEVICE_ERROR;
	}
	if (id == 4) {
		trace("software-session");
	}
	*out = id;
	return CKR_OK;
}
static CK_RV close_session(CK_SESSION_HANDLE session) {
	(void)session;
	return CKR_OK;
}
static CK_RV find_init(
    CK_SESSION_HANDLE session,
    CK_ATTRIBUTE_PTR  attrs,
    CK_ULONG          count
) {
	(void)session;
	found = 0;
	selected = CKO_DATA;
	for (CK_ULONG n = 0; n < count; ++n) {
		if (attrs[n].type == CKA_CLASS) {
			memcpy(&selected, attrs[n].pValue, sizeof(selected));
		}
	}
	return CKR_OK;
}
static CK_RV find(
    CK_SESSION_HANDLE    session,
    CK_OBJECT_HANDLE_PTR objects,
    CK_ULONG             max,
    CK_ULONG_PTR         count
) {
	(void)session;
	CK_OBJECT_HANDLE handles[2];
	CK_ULONG         size = 1;
	switch (selected) {
	case CKO_CERTIFICATE:
		handles[0] = 1;
		handles[1] = 6;
		size = 2;
		break;
	case CKO_PUBLIC_KEY:
		handles[0] = 2;
		handles[1] = 4;
		size = 2;
		break;
	case CKO_PRIVATE_KEY:
		handles[0] = 3;
		break;
	case CKO_SECRET_KEY:
		handles[0] = 5;
		break;
	default:
		*count = 0;
		return CKR_OK;
	}
	if (found >= size) {
		*count = 0;
		return CKR_OK;
	}
	CK_ULONG available = size - found;
	CK_ULONG amount = available < max ? available : max;
	memcpy(objects, handles + found, amount * sizeof(*objects));
	*count = amount;
	found += amount;
	return CKR_OK;
}
static CK_RV attributes(
    CK_SESSION_HANDLE session,
    CK_OBJECT_HANDLE  object,
    CK_ATTRIBUTE_PTR  attrs,
    CK_ULONG          count
) {
	(void)session;
	for (CK_ULONG n = 0; n < count; ++n) {
		CK_ATTRIBUTE*       attr = &attrs[n];
		CK_ULONG            scalar = 0;
		CK_BBOOL            boolean = CK_TRUE;
		unsigned char       id = object == 3 ? 1 : (unsigned char)object;
		const unsigned char ec[] = {6, 8, 42, 134, 72, 206, 61, 3, 1, 7};
		const void*         data = NULL;
		size_t              size = 0;
		const char*         label = object == 1   ? "Certificate <&>"
		                            : object == 6 ? "Malformed certificate"
		                                          : "Key <&>";
		switch (attr->type) {
		case CKA_ID:
			data = &id;
			size = 1;
			break;
		case CKA_LABEL:
			data = label;
			size = strlen(label);
			break;
		case CKA_VALUE:
			if (object != 1 && object != 6) {
				abort();
			}
			data = object == 1 ? (const void*)der : (const void*)"invalid";
			size = object == 1 ? der_len : 7;
			break;
		case CKA_KEY_TYPE:
			scalar = object == 4 ? CKK_EC : object == 5 ? CKK_AES : CKK_RSA;
			data = &scalar;
			size = sizeof(scalar);
			break;
		case CKA_MODULUS_BITS:
			if (object != 2) {
				attr->ulValueLen = CK_UNAVAILABLE_INFORMATION;
				return CKR_ATTRIBUTE_TYPE_INVALID;
			}
			scalar = 3072;
			data = &scalar;
			size = sizeof(scalar);
			break;
		case CKA_EC_PARAMS:
			data = ec;
			size = sizeof(ec);
			break;
		case CKA_VALUE_LEN:
			scalar = 32;
			data = &scalar;
			size = sizeof(scalar);
			break;
		case CKA_SIGN:
			data = &boolean;
			size = sizeof(boolean);
			break;
		default:
			attr->ulValueLen = CK_UNAVAILABLE_INFORMATION;
			return CKR_ATTRIBUTE_TYPE_INVALID;
		}
		if (attr->pValue) {
			if (attr->ulValueLen < size) {
				attr->ulValueLen = size;
				return CKR_BUFFER_TOO_SMALL;
			}
			memcpy(attr->pValue, data, size);
		}
		attr->ulValueLen = size;
	}
	return CKR_OK;
}
static CK_RV login(
    CK_SESSION_HANDLE session,
    CK_USER_TYPE      type,
    CK_UTF8CHAR_PTR   pin,
    CK_ULONG          len
) {
	(void)session;
	(void)type;
	(void)pin;
	(void)len;
	abort();
}
static CK_RV slot_event(
    CK_FLAGS       flags,
    CK_SLOT_ID_PTR slot,
    CK_VOID_PTR    reserved
) {
	(void)slot;
	(void)reserved;
	if (flags != CKF_DONT_BLOCK) {
		abort();
	}
	return CKR_FUNCTION_NOT_SUPPORTED;
}
CK_RV                   C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR out);
static CK_FUNCTION_LIST functions = {
    .version = {2, 40},
    .C_Initialize = initialize,
    .C_Finalize = finalize,
    .C_GetInfo = info,
    .C_GetFunctionList = C_GetFunctionList,
    .C_GetSlotList = slots,
    .C_GetSlotInfo = slot_info,
    .C_GetTokenInfo = token_info,
    .C_OpenSession = open_session,
    .C_CloseSession = close_session,
    .C_FindObjectsInit = find_init,
    .C_FindObjects = find,
    .C_FindObjectsFinal = close_session,
    .C_GetAttributeValue = attributes,
    .C_Login = login,
    .C_WaitForSlotEvent = slot_event
};
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR out) {
	*out = &functions;
	return CKR_OK;
}

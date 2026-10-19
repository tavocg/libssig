/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <libssig/internal.h>
#include <stdio.h>
#include <string.h>

#define CHECK(expr)                                                            \
	do {                                                                       \
		if (!(expr)) {                                                         \
			fprintf(stderr, "Failed: %s:%d: %s\n", __FILE__, __LINE__, #expr); \
			return 1;                                                          \
		}                                                                      \
	} while (0)

static CK_ULONG     token_count = 1;
static CK_RV        open_rv = CKR_OK;
static unsigned int opens;
static unsigned int closes;

static CK_RV slots(CK_BBOOL present, CK_SLOT_ID_PTR ids, CK_ULONG_PTR count) {
	(void)present;
	if (!ids) {
		*count = token_count;
		return CKR_OK;
	}
	if (*count < token_count) {
		*count = token_count;
		return CKR_BUFFER_TOO_SMALL;
	}
	for (CK_ULONG i = 0; i < token_count; ++i) {
		ids[i] = i;
	}
	*count = token_count;
	return CKR_OK;
}

static CK_RV info(CK_SLOT_ID slot, CK_TOKEN_INFO_PTR out) {
	(void)slot;
	memset(out, 0, sizeof(*out));
	memset(out->label, ' ', sizeof(out->label));
	memcpy(out->label, "test", 4);
	return CKR_OK;
}

static CK_RV open_session(
    CK_SLOT_ID            slot,
    CK_FLAGS              flags,
    CK_VOID_PTR           app,
    CK_NOTIFY             notify,
    CK_SESSION_HANDLE_PTR handle
) {
	(void)slot;
	(void)app;
	(void)notify;
	++opens;
	if (flags != CKF_SERIAL_SESSION) {
		return CKR_ARGUMENTS_BAD;
	}
	*handle = 42;
	return open_rv;
}

static CK_RV close_session(CK_SESSION_HANDLE handle) {
	if (handle != 42) {
		return CKR_SESSION_HANDLE_INVALID;
	}
	++closes;
	return CKR_OK;
}

int main(void) {
	CK_FUNCTION_LIST module = {0};
	module.C_GetSlotList = slots;
	module.C_GetTokenInfo = info;
	module.C_OpenSession = open_session;
	module.C_CloseSession = close_session;
	CK_FUNCTION_LIST* modules[] = {&module, NULL};
	pkcs11_context    ctx = {.modules = modules};
	pkcs11_session    s = {0};
	CK_RV             rv = CKR_OK;
	CHECK(
	    pkcs11_session_open(&ctx, "pkcs11:token=test", &s, &rv) == LIBSSIG_OK
	);
	CHECK(s.open && opens == 1);
	CHECK(pkcs11_session_close(&s) == CKR_OK);
	CHECK(pkcs11_session_close(&s) == CKR_OK && closes == 1);
	CHECK(
	    pkcs11_session_open(&ctx, "pkcs11:token=other", &s, &rv) ==
	    LIBSSIG_ERROR_NOT_FOUND
	);
	CHECK(pkcs11_session_open(&ctx, "invalid", &s, &rv) == LIBSSIG_ERROR_URI);
	CHECK(
	    pkcs11_session_open(&ctx, "pkcs11:token=test;object=key", &s, &rv) ==
	    LIBSSIG_ERROR_URI
	);
	token_count = 2;
	CHECK(
	    pkcs11_session_open(&ctx, "pkcs11:token=test", &s, &rv) ==
	    LIBSSIG_ERROR_AMBIGUOUS
	);
	CHECK(opens == 1 && !s.open);
	token_count = 1;
	open_rv = CKR_DEVICE_ERROR;
	CHECK(
	    pkcs11_session_open(&ctx, "pkcs11:token=test", &s, &rv) ==
	    LIBSSIG_ERROR_PKCS11
	);
	CHECK(rv == CKR_DEVICE_ERROR && !s.open);
	modules[0] = NULL;
	CHECK(
	    pkcs11_session_open(&ctx, "pkcs11:token=test", &s, &rv) ==
	    LIBSSIG_ERROR_NOT_FOUND
	);
	return 0;
}

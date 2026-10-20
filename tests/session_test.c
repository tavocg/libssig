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
static unsigned int open_count;
static unsigned int close_count;

static CK_RV mock_slots_get(
    CK_BBOOL       present,
    CK_SLOT_ID_PTR out_slots,
    CK_ULONG_PTR   slot_count
) {
	(void)present;
	if (!out_slots) {
		*slot_count = token_count;
		return CKR_OK;
	}

	if (*slot_count < token_count) {
		*slot_count = token_count;
		return CKR_BUFFER_TOO_SMALL;
	}

	for (CK_ULONG i = 0; i < token_count; ++i) {
		out_slots[i] = i;
	}
	*slot_count = token_count;
	return CKR_OK;
}

static CK_RV mock_token_info_get(
    CK_SLOT_ID        slot,
    CK_TOKEN_INFO_PTR out_token_info
) {
	(void)slot;
	memset(out_token_info, 0, sizeof(*out_token_info));
	memset(out_token_info->label, ' ', sizeof(out_token_info->label));
	memcpy(out_token_info->label, "test", 4);
	return CKR_OK;
}

static CK_RV mock_session_open(
    CK_SLOT_ID            slot,
    CK_FLAGS              flags,
    CK_VOID_PTR           application,
    CK_NOTIFY             notify,
    CK_SESSION_HANDLE_PTR handle
) {
	(void)slot;
	(void)application;
	(void)notify;
	++open_count;
	if (flags != CKF_SERIAL_SESSION) {
		return CKR_ARGUMENTS_BAD;
	}
	*handle = 42;
	return open_rv;
}

static CK_RV mock_session_close(CK_SESSION_HANDLE handle) {
	if (handle != 42) {
		return CKR_SESSION_HANDLE_INVALID;
	}
	++close_count;
	return CKR_OK;
}

int main(void) {
	CK_FUNCTION_LIST module = {0};
	module.C_GetSlotList = mock_slots_get;
	module.C_GetTokenInfo = mock_token_info_get;
	module.C_OpenSession = mock_session_open;
	module.C_CloseSession = mock_session_close;
	CK_FUNCTION_LIST*           modules[] = {&module, NULL};
	struct libssig_context_impl impl = {.modules = modules};
	libssig_context             ctx = {.impl = &impl};
	libssig_session             s = {0};
	CK_RV                       rv = CKR_OK;
	CHECK(
	    libssig_session_open(&ctx, "pkcs11:token=test", &s, &rv) == LIBSSIG_OK
	);
	CHECK(s.open && open_count == 1);
	CHECK(libssig_session_close(&s) == CKR_OK);
	CHECK(libssig_session_close(&s) == CKR_OK && close_count == 1);
	CHECK(
	    libssig_session_open(&ctx, "pkcs11:token=other", &s, &rv) ==
	    LIBSSIG_ERROR_NOT_FOUND
	);
	CHECK(libssig_session_open(&ctx, "invalid", &s, &rv) == LIBSSIG_ERROR_URI);
	CHECK(
	    libssig_session_open(&ctx, "pkcs11:token=test;object=key", &s, &rv) ==
	    LIBSSIG_ERROR_URI
	);
	token_count = 2;
	CHECK(
	    libssig_session_open(&ctx, "pkcs11:token=test", &s, &rv) ==
	    LIBSSIG_ERROR_AMBIGUOUS
	);
	CHECK(open_count == 1 && !s.open);
	token_count = 1;
	open_rv = CKR_DEVICE_ERROR;
	CHECK(
	    libssig_session_open(&ctx, "pkcs11:token=test", &s, &rv) ==
	    LIBSSIG_ERROR_PKCS11
	);
	CHECK(rv == CKR_DEVICE_ERROR && !s.open);
	modules[0] = NULL;
	CHECK(
	    libssig_session_open(&ctx, "pkcs11:token=test", &s, &rv) ==
	    LIBSSIG_ERROR_NOT_FOUND
	);
	return 0;
}

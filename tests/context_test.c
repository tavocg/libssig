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

static unsigned int      load_count;
static unsigned int      release_count;
static unsigned int      open_count;
static unsigned int      close_count;
static bool              fail_load;
static CK_FLAGS          slot_flags;
static unsigned int      slot_info_count;
static CK_FUNCTION_LIST  module;
static CK_FUNCTION_LIST* modules[] = {&module, NULL};

CK_FUNCTION_LIST** p11_kit_modules_load_and_initialize(int flags) {
	(void)flags;
	++load_count;
	return fail_load ? NULL : modules;
}

void p11_kit_modules_finalize_and_release(CK_FUNCTION_LIST** loaded) {
	if (loaded == modules) {
		++release_count;
	}
}

static CK_RV mock_slots_get(
    CK_BBOOL       present,
    CK_SLOT_ID_PTR slots,
    CK_ULONG_PTR   count
) {
	(void)present;
	if (slots) {
		slots[0] = 1;
	}
	*count = 1;
	return CKR_OK;
}

static CK_RV mock_slot_info_get(CK_SLOT_ID slot, CK_SLOT_INFO_PTR info) {
	(void)slot;
	memset(info, 0, sizeof(*info));
	info->flags = slot_flags;
	++slot_info_count;
	return CKR_OK;
}

static CK_RV mock_token_info_get(CK_SLOT_ID slot, CK_TOKEN_INFO_PTR info) {
	(void)slot;
	memset(info, ' ', sizeof(*info));
	info->flags = 0;
	memcpy(info->label, "test", 4);
	return CKR_OK;
}

static CK_RV mock_session_open(
    CK_SLOT_ID            slot,
    CK_FLAGS              flags,
    CK_VOID_PTR           app,
    CK_NOTIFY             notify,
    CK_SESSION_HANDLE_PTR handle
) {
	(void)slot;
	(void)flags;
	(void)app;
	(void)notify;
	++open_count;
	*handle = 42;
	return CKR_OK;
}

static CK_RV mock_session_close(CK_SESSION_HANDLE handle) {
	(void)handle;
	++close_count;
	return CKR_OK;
}

static CK_RV mock_objects_find_init(
    CK_SESSION_HANDLE handle,
    CK_ATTRIBUTE_PTR  attrs,
    CK_ULONG          count
) {
	(void)handle;
	(void)attrs;
	(void)count;
	return CKR_OK;
}

static CK_RV mock_objects_find(
    CK_SESSION_HANDLE    handle,
    CK_OBJECT_HANDLE_PTR objects,
    CK_ULONG             capacity,
    CK_ULONG_PTR         count
) {
	(void)handle;
	(void)objects;
	(void)capacity;
	*count = 0;
	return CKR_OK;
}

static CK_RV mock_objects_find_final(CK_SESSION_HANDLE handle) {
	(void)handle;
	return CKR_OK;
}

int main(void) {
	module.C_GetSlotList = mock_slots_get;
	module.C_GetSlotInfo = mock_slot_info_get;
	module.C_GetTokenInfo = mock_token_info_get;
	module.C_OpenSession = mock_session_open;
	module.C_CloseSession = mock_session_close;
	module.C_FindObjectsInit = mock_objects_find_init;
	module.C_FindObjects = mock_objects_find;
	module.C_FindObjectsFinal = mock_objects_find_final;
	libssig_context          ctx = {0}, next = {0};
	libssig_token_list       tokens = {0};
	libssig_certificate_list certs = {0};
	libssig_token            token = {.uri = "pkcs11:token=test"};
	CHECK(libssig_context_open(NULL) == LIBSSIG_ERROR_ARGUMENT);
	libssig_context_close(NULL);
	libssig_context_close(&ctx);
	CHECK(
	    libssig_tokens(&ctx, &tokens, LIBSSIG_TOKENS_ALL) ==
	    LIBSSIG_ERROR_ARGUMENT
	);
	CHECK(libssig_certificates(&ctx, &token, &certs) == LIBSSIG_ERROR_ARGUMENT);

	fail_load = true;
	CHECK(libssig_context_open(&ctx) == LIBSSIG_ERROR_MODULES && !ctx.impl);

	fail_load = false;

	CHECK(libssig_context_open(&ctx) == LIBSSIG_OK);
	CHECK(libssig_context_open(&ctx) == LIBSSIG_ERROR_ARGUMENT);
	CHECK(load_count == 2);

	for (unsigned int i = 0; i < 2; ++i) {
		CHECK(libssig_tokens(&ctx, &tokens, LIBSSIG_TOKENS_ALL) == LIBSSIG_OK);
		CHECK(tokens.count == 1);
		CHECK(
		    libssig_certificates(&ctx, &tokens.items[0], &certs) == LIBSSIG_OK
		);
		CHECK(certs.count == 0 && certs.ck_rv == CKR_OK);
		libssig_certificates_free(&certs);
		libssig_tokens_free(&tokens);
	}
	CHECK(slot_info_count == 0);
	CHECK(libssig_tokens(&ctx, &tokens, ~0u) == LIBSSIG_ERROR_ARGUMENT);
	CHECK(!tokens.items && !tokens.count && !tokens.ck_rv);
	CHECK(slot_info_count == 0);

	slot_flags = 0;
	CHECK(
	    libssig_tokens(&ctx, &tokens, LIBSSIG_TOKENS_HARDWARE_ONLY) ==
	    LIBSSIG_OK
	);
	CHECK(!tokens.items && !tokens.count && slot_info_count == 1);
	libssig_tokens_free(&tokens);

	slot_flags = CKF_HW_SLOT;
	CHECK(
	    libssig_tokens(&ctx, &tokens, LIBSSIG_TOKENS_HARDWARE_ONLY) ==
	    LIBSSIG_OK
	);
	CHECK(tokens.count == 1 && slot_info_count == 2);
	libssig_tokens_free(&tokens);
	CHECK(load_count == 2 && release_count == 0);
	CHECK(open_count == 2 && close_count == 2);

	CHECK(libssig_context_open(&next) == LIBSSIG_OK);
	libssig_context_close(&next);
	CHECK(libssig_tokens(&ctx, &tokens, LIBSSIG_TOKENS_ALL) == LIBSSIG_OK);
	libssig_context_close(&ctx);
	CHECK(!ctx.impl && release_count == 2);
	CHECK(!strcmp(tokens.items[0].label, "test"));
	libssig_tokens_free(&tokens);
	libssig_context_close(&ctx);
	CHECK(release_count == 2);
	CHECK(libssig_certificates(&ctx, &token, &certs) == LIBSSIG_ERROR_ARGUMENT);

	CHECK(libssig_context_open(&ctx) == LIBSSIG_OK);
	libssig_context_close(&ctx);
	CHECK(load_count == 4 && release_count == 3);
	return 0;
}

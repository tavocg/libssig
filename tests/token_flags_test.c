/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <libssig/internal.h>
#include <limits.h>
#include <p11-kit/p11-kit.h>
#include <stdio.h>
#include <string.h>

#define CHECK(expr)                                                            \
	do {                                                                       \
		if (!(expr)) {                                                         \
			fprintf(stderr, "Failed: %s:%d: %s\n", __FILE__, __LINE__, #expr); \
			return 1;                                                          \
		}                                                                      \
	} while (0)

static unsigned long token_flags;
static CK_RV         mock_slots_get(
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
static CK_RV mock_token_info_get(CK_SLOT_ID slot, CK_TOKEN_INFO_PTR info) {
	(void)slot;
	memset(info, 0, sizeof(*info));
	info->flags = token_flags;
	return CKR_OK;
}
static libssig_token_list tokens;
static libssig_status     token_query(
        unsigned long        flags,
        libssig_string_list* names
    ) {
	CK_FUNCTION_LIST module = {0};
	module.C_GetSlotList = mock_slots_get;
	module.C_GetTokenInfo = mock_token_info_get;
	CK_FUNCTION_LIST*           modules[] = {&module, NULL};
	struct libssig_context_impl impl = {.modules = modules};
	libssig_context             ctx = {.impl = &impl};
	token_flags = flags;
	libssig_status status = libssig_tokens(&ctx, &tokens, LIBSSIG_TOKENS_ALL);
	if (status == LIBSSIG_OK && tokens.count == 1) {
		*names = tokens.items[0].flag_names;
	} else if (status == LIBSSIG_OK) {
		return LIBSSIG_ERROR_NOT_FOUND;
	}
	return status;
}

int main(void) {
	libssig_string_list names = {0};
	CHECK(token_query(0, &names) == LIBSSIG_OK);
	CHECK(!names.items && !names.count);

	CHECK(token_query(CKF_RNG | CKF_LOGIN_REQUIRED, &names) == LIBSSIG_OK);
	CHECK(names.count == 2);
	CHECK(!strcmp(names.items[0], "rng"));
	CHECK(!strcmp(names.items[1], "login-required"));
	libssig_tokens_free(&tokens);
	CHECK(!tokens.items && !tokens.count);
	libssig_tokens_free(&tokens);
	libssig_tokens_free(NULL);

	CHECK(token_query(ULONG_MAX, &names) == LIBSSIG_OK);
	CHECK(names.count > 0 && names.count <= sizeof(unsigned long) * CHAR_BIT);
	for (size_t i = 0; i < names.count; ++i) {
		CHECK(names.items[i] && names.items[i][0]);
		for (size_t j = 0; j < i; ++j) {
			CHECK(strcmp(names.items[i], names.items[j]));
		}
	}
	size_t total = names.count;
	libssig_tokens_free(&tokens);
	size_t        recognized = 0;
	unsigned long unknown = 0;
	for (size_t i = 0; i < sizeof(unsigned long) * CHAR_BIT; ++i) {
		unsigned long flag = 1UL << i;
		CHECK(token_query(flag, &names) == LIBSSIG_OK);
		CHECK(names.count <= 1);
		if (names.count) {
			++recognized;
		} else {
			unknown |= flag;
		}
		libssig_tokens_free(&tokens);
	}
	CHECK(recognized == total);

	CHECK(token_query(unknown, &names) == LIBSSIG_OK);
	CHECK(!names.items && !names.count);

	CHECK(token_query(unknown | CKF_RNG, &names) == LIBSSIG_OK);
	CHECK(names.count == 1 && !strcmp(names.items[0], "rng"));
	libssig_tokens_free(&tokens);
	return 0;
}

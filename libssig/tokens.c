/*
 * This file is part of libssig.
 * Copyright (C) 2026 Gustavo Calvo <tavo@tavo.cr>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * See libssig/libssig.c for the full copyright and warranty notice.
 * See LICENSE in the project root for the GNU General Public License.
 */

#include <libssig/internal.h>
#include <limits.h>
#include <p11-kit/p11-kit.h>
#include <p11-kit/uri.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static void string_list_free(libssig_string_list* names) {
	if (!names) {
		return;
	}

	free(names->items);
	*names = (libssig_string_list){0};
}

static libssig_status token_flags_names(
    unsigned long        flags,
    libssig_string_list* names
) {
	if (!names) {
		return LIBSSIG_ERROR_ARGUMENT;
	}

	*names = (libssig_string_list){0};
	static const struct {
		unsigned long value;
		const char*   name;
	} flag_names[] = {
	    {CKF_RNG, "rng"},
	    {CKF_WRITE_PROTECTED, "write-protected"},
	    {CKF_LOGIN_REQUIRED, "login-required"},
	    {CKF_USER_PIN_INITIALIZED, "user-pin-initialized"},
	    {CKF_RESTORE_KEY_NOT_NEEDED, "restore-key-not-needed"},
	    {CKF_CLOCK_ON_TOKEN, "clock-on-token"},
	    {CKF_PROTECTED_AUTHENTICATION_PATH, "protected-authentication-path"},
	    {CKF_DUAL_CRYPTO_OPERATIONS, "dual-crypto-operations"},
	    {CKF_TOKEN_INITIALIZED, "token-initialized"},
	    {CKF_SECONDARY_AUTHENTICATION, "secondary-authentication"},
	    {CKF_USER_PIN_COUNT_LOW, "user-pin-count-low"},
	    {CKF_USER_PIN_FINAL_TRY, "user-pin-final-try"},
	    {CKF_USER_PIN_LOCKED, "user-pin-locked"},
	    {CKF_USER_PIN_TO_BE_CHANGED, "user-pin-to-be-changed"},
	    {CKF_SO_PIN_COUNT_LOW, "so-pin-count-low"},
	    {CKF_SO_PIN_FINAL_TRY, "so-pin-final-try"},
	    {CKF_SO_PIN_LOCKED, "so-pin-locked"},
	    {CKF_SO_PIN_TO_BE_CHANGED, "so-pin-to-be-changed"},
	    {CKF_ERROR_STATE, "error-state"},
	};
	size_t count = 0;
	for (size_t i = 0; i < sizeof(flag_names) / sizeof(flag_names[0]); ++i) {
		if (flags & flag_names[i].value) {
			++count;
		}
	}

	if (count > sizeof(flags) * CHAR_BIT ||
	    count > SIZE_MAX / sizeof(*names->items)) {
		return LIBSSIG_ERROR_MEMORY;
	}

	if (!count) {
		return LIBSSIG_OK;
	}
	names->items = malloc(count * sizeof(*names->items));
	if (!names->items) {
		return LIBSSIG_ERROR_MEMORY;
	}

	for (size_t i = 0; i < sizeof(flag_names) / sizeof(flag_names[0]); ++i) {
		if (flags & flag_names[i].value) {
			names->items[names->count++] = flag_names[i].name;
		}
	}
	return LIBSSIG_OK;
}

static libssig_status slots_allocate(
    CK_ULONG     slot_count,
    CK_SLOT_ID** out_slots
) {
	*out_slots = NULL;

	if (slot_count == 0) {
		return LIBSSIG_OK;
	}

	if (slot_count > SIZE_MAX / sizeof(**out_slots)) {
		return LIBSSIG_ERROR_MEMORY;
	}

	*out_slots = malloc((size_t)slot_count * sizeof(**out_slots));
	return *out_slots ? LIBSSIG_OK : LIBSSIG_ERROR_MEMORY;
}

static libssig_status token_slots_read(
    CK_FUNCTION_LIST* module,
    CK_SLOT_ID*       slots,
    CK_ULONG*         out_count,
    CK_RV*            out_rv
) {
	*out_rv = module->C_GetSlotList(CK_TRUE, slots, out_count);
	return *out_rv == CKR_OK ? LIBSSIG_OK : LIBSSIG_ERROR_PKCS11;
}

static libssig_status token_slots_get(
    CK_FUNCTION_LIST* module,
    CK_SLOT_ID**      out_slots,
    CK_ULONG*         out_count,
    CK_RV*            out_rv
) {
	*out_slots = NULL;
	*out_count = 0;
	*out_rv = CKR_OK;

	CK_ULONG       slot_count = 0;
	libssig_status status = token_slots_read(module, NULL, &slot_count, out_rv);
	if (status != LIBSSIG_OK || slot_count == 0) {
		return status;
	}

	CK_SLOT_ID* slots = NULL;
	status = slots_allocate(slot_count, &slots);
	if (status != LIBSSIG_OK) {
		return status;
	}

	status = token_slots_read(module, slots, &slot_count, out_rv);
	if (status != LIBSSIG_OK) {
		free(slots);
		return status;
	}

	*out_slots = slots;
	*out_count = slot_count;
	return LIBSSIG_OK;
}

static char* token_text_copy(const CK_UTF8CHAR* text, size_t len) {
	while (len > 0 && text[len - 1] == ' ') {
		--len;
	}

	char* copy = malloc(len + 1);
	if (!copy) {
		return NULL;
	}

	memcpy(copy, text, len);
	copy[len] = '\0';
	return copy;
}

static void token_free(libssig_token* token) {
	free(token->uri);
	free(token->label);
	free(token->manufacturer);
	free(token->model);
	free(token->serial);
	string_list_free(&token->flag_names);
	*token = (libssig_token){0};
}

static libssig_status token_uri_create(
    const CK_TOKEN_INFO* token_info,
    char**               out_uri
) {
	*out_uri = NULL;
	P11KitUri* uri = p11_kit_uri_new();
	if (!uri) {
		return LIBSSIG_ERROR_MEMORY;
	}

	*p11_kit_uri_get_token_info(uri) = *token_info;
	int uri_status = p11_kit_uri_format(uri, P11_KIT_URI_FOR_TOKEN, out_uri);
	p11_kit_uri_free(uri);

	if (uri_status == P11_KIT_URI_NO_MEMORY) {
		return LIBSSIG_ERROR_MEMORY;
	}
	return uri_status == P11_KIT_URI_OK ? LIBSSIG_OK : LIBSSIG_ERROR_URI;
}

static libssig_status token_from_info(
    const CK_TOKEN_INFO* token_info,
    libssig_token*       token
) {
	*token = (libssig_token){0};
	token->label = token_text_copy(
	    token_info->label,
	    sizeof(token_info->label)
	);
	token->manufacturer = token_text_copy(
	    token_info->manufacturerID,
	    sizeof(token_info->manufacturerID)
	);
	token->model = token_text_copy(
	    token_info->model,
	    sizeof(token_info->model)
	);
	token->serial = token_text_copy(
	    token_info->serialNumber,
	    sizeof(token_info->serialNumber)
	);
	token->flags = token_info->flags;
	token->max_session_count = token_info->ulMaxSessionCount;
	token->session_count = token_info->ulSessionCount;
	token->max_rw_session_count = token_info->ulMaxRwSessionCount;
	token->rw_session_count = token_info->ulRwSessionCount;
	token->max_pin_len = token_info->ulMaxPinLen;
	token->min_pin_len = token_info->ulMinPinLen;
	token->total_public_memory = token_info->ulTotalPublicMemory;
	token->free_public_memory = token_info->ulFreePublicMemory;
	token->total_private_memory = token_info->ulTotalPrivateMemory;
	token->free_private_memory = token_info->ulFreePrivateMemory;
	token->hardware_version = (libssig_token_version){
	    token_info->hardwareVersion.major,
	    token_info->hardwareVersion.minor
	};
	token->firmware_version = (libssig_token_version){
	    token_info->firmwareVersion.major,
	    token_info->firmwareVersion.minor
	};

	if (token_info->flags & CKF_CLOCK_ON_TOKEN) {
		memcpy(
		    token->utc_time,
		    token_info->utcTime,
		    sizeof(token_info->utcTime)
		);
	}

	if (!token->label || !token->manufacturer || !token->model ||
	    !token->serial) {
		token_free(token);
		return LIBSSIG_ERROR_MEMORY;
	}

	libssig_status status = token_flags_names(token->flags, &token->flag_names);
	if (status != LIBSSIG_OK) {
		token_free(token);
		return status;
	}

	status = token_uri_create(token_info, &token->uri);
	if (status != LIBSSIG_OK) {
		token_free(token);
	}
	return status;
}

static libssig_status tokens_append(
    libssig_token_list* tokens,
    libssig_token*      token
) {
	if (tokens->count >= SIZE_MAX / sizeof(*tokens->items)) {
		return LIBSSIG_ERROR_MEMORY;
	}

	libssig_token* items = realloc(
	    tokens->items,
	    (tokens->count + 1) * sizeof(*items)
	);
	if (!items) {
		return LIBSSIG_ERROR_MEMORY;
	}

	tokens->items = items;
	tokens->items[tokens->count++] = *token;
	*token = (libssig_token){0};
	return LIBSSIG_OK;
}

static libssig_status slot_is_hardware(
    CK_FUNCTION_LIST* module,
    CK_SLOT_ID        slot,
    CK_BBOOL*         out_hardware,
    CK_RV*            out_rv
) {
	*out_hardware = CK_FALSE;
	CK_SLOT_INFO slot_info;
	*out_rv = module->C_GetSlotInfo(slot, &slot_info);
	if (*out_rv != CKR_OK) {
		return LIBSSIG_ERROR_PKCS11;
	}

	*out_hardware = (slot_info.flags & CKF_HW_SLOT) ? CK_TRUE : CK_FALSE;
	return LIBSSIG_OK;
}

static libssig_status tokens_collect_one(
    CK_FUNCTION_LIST*   module,
    CK_SLOT_ID          slot,
    libssig_token_list* tokens
) {
	CK_TOKEN_INFO token_info;
	CK_RV         rv = module->C_GetTokenInfo(slot, &token_info);

	if (rv == CKR_TOKEN_NOT_PRESENT) {
		return LIBSSIG_OK;
	}

	if (rv != CKR_OK) {
		tokens->ck_rv = rv;
		return LIBSSIG_ERROR_PKCS11;
	}

	libssig_token  token = {0};
	libssig_status status = token_from_info(&token_info, &token);
	if (status != LIBSSIG_OK) {
		return status;
	}

	status = tokens_append(tokens, &token);
	token_free(&token);
	return status;
}

static libssig_status slot_token_collect(
    CK_FUNCTION_LIST*   module,
    CK_SLOT_ID          slot,
    bool                hardware_only,
    libssig_token_list* tokens
) {
	if (!hardware_only) {
		return tokens_collect_one(module, slot, tokens);
	}

	CK_BBOOL       hardware = CK_FALSE;
	CK_RV          rv = CKR_OK;
	libssig_status status = slot_is_hardware(module, slot, &hardware, &rv);
	if (status != LIBSSIG_OK) {
		tokens->ck_rv = rv;
		return status;
	}

	if (!hardware) {
		return LIBSSIG_OK;
	}

	return tokens_collect_one(module, slot, tokens);
}

static libssig_status module_tokens_collect(
    CK_FUNCTION_LIST*   module,
    bool                hardware_only,
    libssig_token_list* tokens
) {
	CK_SLOT_ID*    slots = NULL;
	CK_ULONG       slot_count = 0;
	CK_RV          rv = CKR_OK;
	libssig_status status = token_slots_get(module, &slots, &slot_count, &rv);
	if (status != LIBSSIG_OK) {
		tokens->ck_rv = rv;
		return status;
	}

	for (CK_ULONG i = 0; i < slot_count; ++i) {
		status = slot_token_collect(module, slots[i], hardware_only, tokens);
		if (status != LIBSSIG_OK) {
			break;
		}
	}

	free(slots);
	return status;
}

void libssig_tokens_free(libssig_token_list* tokens) {
	if (!tokens) {
		return;
	}

	for (size_t i = 0; i < tokens->count; ++i) {
		token_free(&tokens->items[i]);
	}

	free(tokens->items);
	*tokens = (libssig_token_list){0};
}

libssig_status libssig_tokens(
    const libssig_context* ctx,
    libssig_token_list*    tokens,
    bool                   hardware_only
) {
	if (!tokens) {
		return LIBSSIG_ERROR_ARGUMENT;
	}

	*tokens = (libssig_token_list){0};

	if (!ctx || !ctx->impl || !ctx->impl->modules) {
		return LIBSSIG_ERROR_ARGUMENT;
	}

	libssig_status status = LIBSSIG_OK;

	libssig_token_list collected = {0};
	for (size_t i = 0; ctx->impl->modules[i] != NULL; ++i) {
		status = module_tokens_collect(
		    ctx->impl->modules[i],
		    hardware_only,
		    &collected
		);
		if (status != LIBSSIG_OK) {
			break;
		}
	}

	if (status != LIBSSIG_OK) {
		unsigned long ck_rv = collected.ck_rv;
		libssig_tokens_free(&collected);
		*tokens = (libssig_token_list){.ck_rv = ck_rv};
		return status;
	}

	*tokens = collected;
	return LIBSSIG_OK;
}

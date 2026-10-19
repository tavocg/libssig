/*
 * This file is part of libssig.
 * Copyright (C) 2026 Gustavo Calvo <tavo@tavo.cr>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * See libssig/libssig.c for the full copyright and warranty notice.
 * See LICENSE in the project root for the GNU General Public License.
 */

#include <libssig/internal.h>
#include <p11-kit/p11-kit.h>
#include <p11-kit/uri.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static libssig_status allocate_slots(CK_ULONG count, CK_SLOT_ID** out_slots) {
	*out_slots = NULL;

	if (count == 0) {
		return LIBSSIG_OK;
	}

	if (count > SIZE_MAX / sizeof(**out_slots)) {
		return LIBSSIG_ERROR_MEMORY;
	}

	*out_slots = malloc((size_t)count * sizeof(**out_slots));
	return *out_slots ? LIBSSIG_OK : LIBSSIG_ERROR_MEMORY;
}

static libssig_status read_token_slots(
	CK_FUNCTION_LIST* module,
	CK_SLOT_ID*		  slots,
	CK_ULONG*		  count,
	CK_RV*			  out_rv
) {
	*out_rv = module->C_GetSlotList(CK_TRUE, slots, count);
	return *out_rv == CKR_OK ? LIBSSIG_OK : LIBSSIG_ERROR_PKCS11;
}

static libssig_status get_token_slots(
	CK_FUNCTION_LIST* module,
	CK_SLOT_ID**	  out_slots,
	CK_ULONG*		  out_count,
	CK_RV*			  out_rv
) {
	*out_slots = NULL;
	*out_count = 0;
	*out_rv = CKR_OK;

	CK_ULONG	   count = 0;
	libssig_status status = read_token_slots(module, NULL, &count, out_rv);
	if (status != LIBSSIG_OK || count == 0) {
		return status;
	}

	CK_SLOT_ID* slots = NULL;
	status = allocate_slots(count, &slots);
	if (status != LIBSSIG_OK) {
		return status;
	}

	status = read_token_slots(module, slots, &count, out_rv);
	if (status != LIBSSIG_OK) {
		free(slots);
		return status;
	}

	*out_slots = slots;
	*out_count = count;
	return LIBSSIG_OK;
}

static char* copy_token_text(const CK_UTF8CHAR* text, size_t length) {
	while (length > 0 && text[length - 1] == ' ') {
		--length;
	}

	char* copy = malloc(length + 1);
	if (!copy) {
		return NULL;
	}

	memcpy(copy, text, length);
	copy[length] = '\0';
	return copy;
}

static void token_free(libssig_token* token) {
	free(token->uri);
	free(token->label);
	free(token->manufacturer);
	free(token->model);
	free(token->serial);
	*token = (libssig_token){0};
}

static libssig_status create_token_uri(
	const CK_TOKEN_INFO* info,
	char**				 out_uri
) {
	*out_uri = NULL;
	P11KitUri* uri = p11_kit_uri_new();
	if (!uri) {
		return LIBSSIG_ERROR_MEMORY;
	}

	*p11_kit_uri_get_token_info(uri) = *info;
	int rc = p11_kit_uri_format(uri, P11_KIT_URI_FOR_TOKEN, out_uri);
	p11_kit_uri_free(uri);

	if (rc == P11_KIT_URI_NO_MEMORY) {
		return LIBSSIG_ERROR_MEMORY;
	}
	return rc == P11_KIT_URI_OK ? LIBSSIG_OK : LIBSSIG_ERROR_URI;
}

static libssig_status token_from_info(
	const CK_TOKEN_INFO* info,
	libssig_token*		 token
) {
	*token = (libssig_token){0};
	token->label = copy_token_text(info->label, sizeof(info->label));
	token->manufacturer =
		copy_token_text(info->manufacturerID, sizeof(info->manufacturerID));
	token->model = copy_token_text(info->model, sizeof(info->model));
	token->serial =
		copy_token_text(info->serialNumber, sizeof(info->serialNumber));
	token->flags = info->flags;
	token->max_session_count = info->ulMaxSessionCount;
	token->session_count = info->ulSessionCount;
	token->max_rw_session_count = info->ulMaxRwSessionCount;
	token->rw_session_count = info->ulRwSessionCount;
	token->max_pin_len = info->ulMaxPinLen;
	token->min_pin_len = info->ulMinPinLen;
	token->total_public_memory = info->ulTotalPublicMemory;
	token->free_public_memory = info->ulFreePublicMemory;
	token->total_private_memory = info->ulTotalPrivateMemory;
	token->free_private_memory = info->ulFreePrivateMemory;
	token->hardware_version =
		(libssig_version_info){info->hardwareVersion.major,
							   info->hardwareVersion.minor};
	token->firmware_version =
		(libssig_version_info){info->firmwareVersion.major,
							   info->firmwareVersion.minor};
	if (info->flags & CKF_CLOCK_ON_TOKEN) {
		memcpy(token->utc_time, info->utcTime, sizeof(info->utcTime));
	}

	if (!token->label || !token->manufacturer || !token->model ||
		!token->serial) {
		token_free(token);
		return LIBSSIG_ERROR_MEMORY;
	}

	libssig_status status = create_token_uri(info, &token->uri);
	if (status != LIBSSIG_OK) {
		token_free(token);
	}
	return status;
}

static libssig_status append_token(
	libssig_tokens* result,
	libssig_token*	token
) {
	if (result->count >= SIZE_MAX / sizeof(*result->items)) {
		return LIBSSIG_ERROR_MEMORY;
	}

	libssig_token* items =
		realloc(result->items, (result->count + 1) * sizeof(*items));
	if (!items) {
		return LIBSSIG_ERROR_MEMORY;
	}

	result->items = items;
	result->items[result->count++] = *token;
	*token = (libssig_token){0};
	return LIBSSIG_OK;
}

static libssig_status slot_is_hardware(
	CK_FUNCTION_LIST* module,
	CK_SLOT_ID		  slot,
	CK_BBOOL*		  out_hardware,
	CK_RV*			  out_rv
) {
	*out_hardware = CK_FALSE;
	CK_SLOT_INFO info;
	*out_rv = module->C_GetSlotInfo(slot, &info);
	if (*out_rv != CKR_OK) {
		return LIBSSIG_ERROR_PKCS11;
	}

	*out_hardware = (info.flags & CKF_HW_SLOT) ? CK_TRUE : CK_FALSE;
	return LIBSSIG_OK;
}

static libssig_status collect_token(
	CK_FUNCTION_LIST* module,
	CK_SLOT_ID		  slot,
	libssig_tokens*	  result
) {
	CK_TOKEN_INFO info;
	CK_RV		  rv = module->C_GetTokenInfo(slot, &info);

	if (rv == CKR_TOKEN_NOT_PRESENT) {
		return LIBSSIG_OK;
	}

	if (rv != CKR_OK) {
		result->ck_rv = rv;
		return LIBSSIG_ERROR_PKCS11;
	}

	libssig_token  token = {0};
	libssig_status status = token_from_info(&info, &token);
	if (status != LIBSSIG_OK) {
		return status;
	}

	status = append_token(result, &token);
	token_free(&token);
	return status;
}

static libssig_status collect_slot_token(
	CK_FUNCTION_LIST* module,
	CK_SLOT_ID		  slot,
	bool			  hardware_only,
	libssig_tokens*	  result
) {
	if (!hardware_only) {
		return collect_token(module, slot, result);
	}

	CK_BBOOL	   hardware = CK_FALSE;
	CK_RV		   rv = CKR_OK;
	libssig_status status = slot_is_hardware(module, slot, &hardware, &rv);
	if (status != LIBSSIG_OK) {
		result->ck_rv = rv;
		return status;
	}
	if (!hardware) {
		return LIBSSIG_OK;
	}

	return collect_token(module, slot, result);
}

static libssig_status collect_module_tokens(
	CK_FUNCTION_LIST* module,
	bool			  hardware_only,
	libssig_tokens*	  result
) {
	CK_SLOT_ID*	   slots = NULL;
	CK_ULONG	   count = 0;
	CK_RV		   rv = CKR_OK;
	libssig_status status = get_token_slots(module, &slots, &count, &rv);
	if (status != LIBSSIG_OK) {
		result->ck_rv = rv;
		return status;
	}

	for (CK_ULONG i = 0; i < count; ++i) {
		status = collect_slot_token(module, slots[i], hardware_only, result);
		if (status != LIBSSIG_OK) {
			break;
		}
	}

	free(slots);
	return status;
}

void libssig_tokens_free(libssig_tokens* result) {
	if (!result) {
		return;
	}

	for (size_t i = 0; i < result->count; ++i) {
		token_free(&result->items[i]);
	}

	free(result->items);
	*result = (libssig_tokens){0};
}

libssig_status libssig_list_tokens(libssig_tokens* result, bool hardware_only) {
	if (!result) {
		return LIBSSIG_ERROR_ARGUMENT;
	}

	*result = (libssig_tokens){0};

	pkcs11_context ctx = {0};
	libssig_status status = pkcs11_context_open(&ctx);

	if (status != LIBSSIG_OK) {
		return status;
	}

	libssig_tokens collected = {0};
	for (size_t m = 0; ctx.modules[m] != NULL; ++m) {
		status =
			collect_module_tokens(ctx.modules[m], hardware_only, &collected);
		if (status != LIBSSIG_OK) {
			break;
		}
	}

	pkcs11_context_close(&ctx);

	if (status != LIBSSIG_OK) {
		unsigned long ck_rv = collected.ck_rv;
		libssig_tokens_free(&collected);
		*result = (libssig_tokens){.ck_rv = ck_rv};
		return status;
	}

	*result = collected;
	return LIBSSIG_OK;
}

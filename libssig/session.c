/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <libssig/internal.h>
#include <limits.h>
#include <p11-kit/uri.h>
#include <stdint.h>
#include <stdlib.h>

static libssig_status slot_match(
    CK_FUNCTION_LIST* module,
    CK_SLOT_ID        slot,
    P11KitUri*        uri,
    libssig_session*  s,
    CK_RV*            out_rv
) {
	CK_TOKEN_INFO token_info;
	*out_rv = module->C_GetTokenInfo(slot, &token_info);
	if (*out_rv == CKR_TOKEN_NOT_PRESENT) {
		*out_rv = CKR_OK;
		return LIBSSIG_OK;
	}
	if (*out_rv != CKR_OK) {
		return LIBSSIG_ERROR_PKCS11;
	}
	if (!p11_kit_uri_match_token_info(uri, &token_info)) {
		return LIBSSIG_OK;
	}
	if (s->module) {
		return LIBSSIG_ERROR_AMBIGUOUS;
	}
	s->module = module;
	s->slot = slot;
	return LIBSSIG_OK;
}

static libssig_status module_token_find(
    CK_FUNCTION_LIST* module,
    P11KitUri*        uri,
    libssig_session*  s,
    CK_RV*            out_rv
) {
	CK_ULONG slot_count = 0;
	*out_rv = module->C_GetSlotList(CK_TRUE, NULL, &slot_count);
	if (*out_rv != CKR_OK) {
		return LIBSSIG_ERROR_PKCS11;
	}
	if (!slot_count) {
		return LIBSSIG_OK;
	}
	if (slot_count > SIZE_MAX / sizeof(CK_SLOT_ID)) {
		return LIBSSIG_ERROR_MEMORY;
	}
	CK_SLOT_ID* slots = malloc((size_t)slot_count * sizeof(*slots));
	if (!slots) {
		return LIBSSIG_ERROR_MEMORY;
	}
	*out_rv = module->C_GetSlotList(CK_TRUE, slots, &slot_count);
	libssig_status status = LIBSSIG_ERROR_PKCS11;
	if (*out_rv == CKR_OK) {
		status = LIBSSIG_OK;
		for (CK_ULONG i = 0; i < slot_count; ++i) {
			status = slot_match(module, slots[i], uri, s, out_rv);
			if (status != LIBSSIG_OK) {
				break;
			}
		}
	}
	free(slots);
	return status;
}

static libssig_status token_select(
    const libssig_context* ctx,
    const char*            uri_text,
    libssig_session*       s,
    CK_RV*                 out_rv
) {
	P11KitUri* uri = p11_kit_uri_new();
	if (!uri) {
		return LIBSSIG_ERROR_MEMORY;
	}
	int uri_status = p11_kit_uri_parse(uri_text, P11_KIT_URI_FOR_TOKEN, uri);

	libssig_status status = LIBSSIG_ERROR_URI;
	if (uri_status != P11_KIT_URI_OK || p11_kit_uri_any_unrecognized(uri) ||
	    p11_kit_uri_get_pin_value(uri) || p11_kit_uri_get_pin_source(uri) ||
	    p11_kit_uri_get_module_name(uri) || p11_kit_uri_get_module_path(uri)) {
		p11_kit_uri_free(uri);
		return status;
	}
	status = LIBSSIG_OK;
	for (size_t i = 0; ctx->modules[i]; ++i) {
		status = module_token_find(ctx->modules[i], uri, s, out_rv);
		if (status != LIBSSIG_OK) {
			break;
		}
	}
	p11_kit_uri_free(uri);
	if (status != LIBSSIG_OK) {
		return status;
	}
	return s->module ? LIBSSIG_OK : LIBSSIG_ERROR_NOT_FOUND;
}

libssig_status libssig_session_open(
    const libssig_context* ctx,
    const char*            uri,
    libssig_session*       s,
    CK_RV*                 out_rv
) {
	if (!ctx || !ctx->modules || !uri || !s || !out_rv || s->open) {
		return LIBSSIG_ERROR_ARGUMENT;
	}
	*out_rv = CKR_OK;
	libssig_session pending = {0};
	libssig_status  status = token_select(ctx, uri, &pending, out_rv);
	if (status != LIBSSIG_OK) {
		return status;
	}
	*out_rv = pending.module->C_OpenSession(
	    pending.slot,
	    CKF_SERIAL_SESSION,
	    NULL,
	    NULL,
	    &pending.handle
	);
	if (*out_rv != CKR_OK) {
		return LIBSSIG_ERROR_PKCS11;
	}
	pending.open = true;
	*s = pending;
	return LIBSSIG_OK;
}

libssig_status libssig_session_login(
    libssig_session*     s,
    const unsigned char* pin,
    size_t               pin_len,
    CK_RV*               out_rv
) {
	if (!out_rv) {
		return LIBSSIG_ERROR_ARGUMENT;
	}
	*out_rv = CKR_OK;
	if (!s || !s->open || !s->module || (!pin && pin_len) ||
	    pin_len > ULONG_MAX) {
		return LIBSSIG_ERROR_ARGUMENT;
	}

	CK_TOKEN_INFO token_info;
	*out_rv = s->module->C_GetTokenInfo(s->slot, &token_info);
	if (*out_rv != CKR_OK) {
		return LIBSSIG_ERROR_PKCS11;
	}
	if (!(token_info.flags & CKF_LOGIN_REQUIRED)) {
		return LIBSSIG_OK;
	}
	if (!pin && !(token_info.flags & CKF_PROTECTED_AUTHENTICATION_PATH)) {
		return LIBSSIG_ERROR_ARGUMENT;
	}

	*out_rv = s->module->C_Login(
	    s->handle,
	    CKU_USER,
	    (CK_UTF8CHAR_PTR)pin,
	    (CK_ULONG)pin_len
	);
	if (*out_rv == CKR_OK || *out_rv == CKR_USER_ALREADY_LOGGED_IN) {
		return LIBSSIG_OK;
	}
	return LIBSSIG_ERROR_PKCS11;
}

CK_RV libssig_session_close(libssig_session* s) {
	if (!s || !s->open) {
		return CKR_OK;
	}
	CK_RV rv = s->module->C_CloseSession(s->handle);
	*s = (libssig_session){0};
	return rv;
}

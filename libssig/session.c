/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <libssig/internal.h>
#include <limits.h>
#include <p11-kit/uri.h>
#include <stdint.h>
#include <stdlib.h>

static libssig_status match_slot(
    CK_FUNCTION_LIST* module,
    CK_SLOT_ID        slot,
    P11KitUri*        uri,
    pkcs11_session*   s,
    CK_RV*            out_rv
) {
	CK_TOKEN_INFO info;
	*out_rv = module->C_GetTokenInfo(slot, &info);
	if (*out_rv == CKR_TOKEN_NOT_PRESENT) {
		*out_rv = CKR_OK;
		return LIBSSIG_OK;
	}
	if (*out_rv != CKR_OK) {
		return LIBSSIG_ERROR_PKCS11;
	}
	if (!p11_kit_uri_match_token_info(uri, &info)) {
		return LIBSSIG_OK;
	}
	if (s->module) {
		return LIBSSIG_ERROR_AMBIGUOUS;
	}
	s->module = module;
	s->slot = slot;
	return LIBSSIG_OK;
}

static libssig_status find_in_module(
    CK_FUNCTION_LIST* module,
    P11KitUri*        uri,
    pkcs11_session*   s,
    CK_RV*            out_rv
) {
	CK_ULONG count = 0;
	*out_rv = module->C_GetSlotList(CK_TRUE, NULL, &count);
	if (*out_rv != CKR_OK) {
		return LIBSSIG_ERROR_PKCS11;
	}
	if (!count) {
		return LIBSSIG_OK;
	}
	if (count > SIZE_MAX / sizeof(CK_SLOT_ID)) {
		return LIBSSIG_ERROR_MEMORY;
	}
	CK_SLOT_ID* slots = malloc((size_t)count * sizeof(*slots));
	if (!slots) {
		return LIBSSIG_ERROR_MEMORY;
	}
	*out_rv = module->C_GetSlotList(CK_TRUE, slots, &count);
	libssig_status status = LIBSSIG_ERROR_PKCS11;
	if (*out_rv == CKR_OK) {
		status = LIBSSIG_OK;
		for (CK_ULONG i = 0; i < count; ++i) {
			status = match_slot(module, slots[i], uri, s, out_rv);
			if (status != LIBSSIG_OK) {
				break;
			}
		}
	}
	free(slots);
	return status;
}

static libssig_status select_token(
    const pkcs11_context* ctx,
    const char*           text,
    pkcs11_session*       s,
    CK_RV*                out_rv
) {
	P11KitUri* uri = p11_kit_uri_new();
	if (!uri) {
		return LIBSSIG_ERROR_MEMORY;
	}
	/* Por ahora aceptamos URIs de token; no atributos de objeto ni PIN. */
	int rc = p11_kit_uri_parse(text, P11_KIT_URI_FOR_TOKEN, uri);

	libssig_status status = LIBSSIG_ERROR_URI;
	if (rc != P11_KIT_URI_OK || p11_kit_uri_any_unrecognized(uri) ||
	    p11_kit_uri_get_pin_value(uri) || p11_kit_uri_get_pin_source(uri) ||
	    p11_kit_uri_get_module_name(uri) || p11_kit_uri_get_module_path(uri)) {
		p11_kit_uri_free(uri);
		return status;
	}
	status = LIBSSIG_OK;
	for (size_t i = 0; ctx->modules[i]; ++i) {
		status = find_in_module(ctx->modules[i], uri, s, out_rv);
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

libssig_status pkcs11_session_open(
    const pkcs11_context* ctx,
    const char*           uri,
    pkcs11_session*       s,
    CK_RV*                out_rv
) {
	if (!ctx || !ctx->modules || !uri || !s || !out_rv || s->open) {
		return LIBSSIG_ERROR_ARGUMENT;
	}
	*out_rv = CKR_OK;
	pkcs11_session pending = {0};
	libssig_status status = select_token(ctx, uri, &pending, out_rv);
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

libssig_status pkcs11_session_login(
    pkcs11_session*      s,
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

	CK_TOKEN_INFO info;
	*out_rv = s->module->C_GetTokenInfo(s->slot, &info);
	if (*out_rv != CKR_OK) {
		return LIBSSIG_ERROR_PKCS11;
	}
	if (!(info.flags & CKF_LOGIN_REQUIRED)) {
		return LIBSSIG_OK;
	}
	if (!pin && !(info.flags & CKF_PROTECTED_AUTHENTICATION_PATH)) {
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

CK_RV pkcs11_session_close(pkcs11_session* s) {
	if (!s || !s->open) {
		return CKR_OK;
	}
	CK_RV rv = s->module->C_CloseSession(s->handle);
	*s = (pkcs11_session){0};
	return rv;
}

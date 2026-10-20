/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <libssig/internal.h>
#include <limits.h>
#include <string.h>

static bool mime_type_valid(const char* type) {
	if (!type) {
		return true;
	}

	size_t      len = strlen(type);
	const char* slash = strchr(type, '/');
	if (!len || len > 255 || !slash || slash == type ||
	    slash == type + len - 1) {
		return false;
	}

	for (size_t i = 0; i < len; ++i) {
		if ((unsigned char)type[i] < 0x20 || (unsigned char)type[i] > 0x7e) {
			return false;
		}
	}
	return true;
}

static libssig_status params_check(
    const libssig_context*     ctx,
    const libssig_sign_params* params
) {
	if (!ctx || !ctx->impl || !ctx->impl->modules || !params ||
	    !params->token || !params->token->uri || !params->cert ||
	    !params->cert->id || !params->cert->id_len ||
	    params->cert->id_len > ULONG_MAX || !params->cert->der ||
	    !params->cert->der_len || params->cert->der_len > LONG_MAX ||
	    (params->data_len && !params->data) || params->data_len > INT_MAX ||
	    (params->pin_len && !params->pin) || params->pin_len > ULONG_MAX) {
		return LIBSSIG_ERROR_ARGUMENT;
	}

	if ((params->format != LIBSSIG_FORMAT_CADES &&
	     params->format != LIBSSIG_FORMAT_CMS) ||
	    (params->algo != LIBSSIG_ALGO_RSA_PKCS &&
	     params->algo != LIBSSIG_ALGO_RSA_PSS &&
	     params->algo != LIBSSIG_ALGO_ECDSA) ||
	    (params->hash != LIBSSIG_HASH_SHA256 &&
	     params->hash != LIBSSIG_HASH_SHA384 &&
	     params->hash != LIBSSIG_HASH_SHA512)) {
		return LIBSSIG_ERROR_UNSUPPORTED;
	}

	if (params->options & ~LIBSSIG_SIGN_DETACHED) {
		return LIBSSIG_ERROR_ARGUMENT;
	}

	if (params->format == LIBSSIG_FORMAT_CADES &&
	    !mime_type_valid(params->mime_type)) {
		return LIBSSIG_ERROR_ARGUMENT;
	}
	return LIBSSIG_OK;
}

libssig_status libssig_sign(
    const libssig_context*     ctx,
    const libssig_sign_params* params,
    libssig_signature*         signature
) {
	if (!signature) {
		return LIBSSIG_ERROR_ARGUMENT;
	}

	*signature = (libssig_signature){0};
	libssig_status status = params_check(ctx, params);
	if (status != LIBSSIG_OK) {
		return status;
	}

	libssig_key_sign_params signing = {
	    .token = params->token,
	    .id = params->cert->id,
	    .id_len = params->cert->id_len,
	    .pin = params->pin,
	    .pin_len = params->pin_len,
	    .data = params->data,
	    .data_len = params->data_len,
	    .algo = params->algo,
	    .hash = params->hash,
	    .mime_type = params->mime_type,
	    .options = params->options,
	};
	return params->format == LIBSSIG_FORMAT_CADES
	           ? libssig_cades_sign(ctx, &signing, params->cert, signature)
	           : libssig_cms_sign(ctx, &signing, params->cert, signature);
}

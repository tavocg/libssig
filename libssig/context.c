/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <libssig/internal.h>

libssig_status pkcs11_context_open(pkcs11_context* ctx) {
	if (!ctx || ctx->modules) {
		return LIBSSIG_ERROR_ARGUMENT;
	}
	ctx->modules = p11_kit_modules_load_and_initialize(0);
	return ctx->modules ? LIBSSIG_OK : LIBSSIG_ERROR_MODULES;
}

void pkcs11_context_close(pkcs11_context* ctx) {
	if (!ctx || !ctx->modules) {
		return;
	}
	p11_kit_modules_finalize_and_release(ctx->modules);
	ctx->modules = NULL;
}

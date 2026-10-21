/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <libssig/context/context.h>
#include <libssig/session.h>
#include <stdlib.h>

libssig_status libssig_context_open(libssig_context* ctx) {
	if (!ctx || ctx->impl) {
		return LIBSSIG_ERROR_ARGUMENT;
	}

	struct libssig_context_impl* impl = calloc(1, sizeof(*impl));
	if (!impl) {
		return LIBSSIG_ERROR_MEMORY;
	}

	impl->modules = p11_kit_modules_load_and_initialize(0);
	if (!impl->modules) {
		free(impl);
		return LIBSSIG_ERROR_MODULES;
	}

	ctx->impl = impl;
	return LIBSSIG_OK;
}

void libssig_context_close(libssig_context* ctx) {
	if (!ctx || !ctx->impl) {
		return;
	}

	p11_kit_modules_finalize_and_release(ctx->impl->modules);
	free(ctx->impl);
	ctx->impl = NULL;
}

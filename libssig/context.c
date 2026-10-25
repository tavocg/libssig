/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <libssig/context.h>
#include <libssig/provider.h>
#include <libssig/session.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static void context_free(struct libssig_context_impl* impl) {
	if (impl->managed_modules) {
		free(impl->modules);
		impl->modules = impl->managed_modules;
	}
	if (impl->explicit_modules) {
		if (impl->modules) {
			for (size_t i = 0; impl->modules[i]; ++i) {
				p11_kit_module_finalize(impl->modules[i]);
				p11_kit_module_release(impl->modules[i]);
			}
		}
		free(impl->modules);
	} else if (impl->modules) {
		p11_kit_modules_finalize_and_release(impl->modules);
	}
	free(impl);
}

libssig_status libssig_context_open_modules(
    libssig_context*           ctx,
    const libssig_string_list* paths
) {
	if (!ctx || ctx->impl || (paths && paths->count && !paths->items)) {
		return LIBSSIG_ERROR_ARGUMENT;
	}
	if (paths && paths->count >= SIZE_MAX / sizeof(CK_FUNCTION_LIST*)) {
		return LIBSSIG_ERROR_MEMORY;
	}
	for (size_t i = 0; paths && i < paths->count; ++i) {
		if (!paths->items[i] || !paths->items[i][0]) {
			return LIBSSIG_ERROR_ARGUMENT;
		}
	}
	struct libssig_context_impl* impl = calloc(1, sizeof(*impl));
	if (!impl) {
		return LIBSSIG_ERROR_MEMORY;
	}
	impl->explicit_modules = paths && paths->count;
	if (!impl->explicit_modules) {
		impl->modules = p11_kit_modules_load_and_initialize(0);
		if (!impl->modules) {
			context_free(impl);
			return LIBSSIG_ERROR_MODULES;
		}
	} else {
		impl->modules = calloc(paths->count + 1, sizeof(*impl->modules));
		if (!impl->modules) {
			context_free(impl);
			return LIBSSIG_ERROR_MEMORY;
		}
		size_t count = 0;
		for (size_t i = 0; i < paths->count; ++i) {
			bool duplicate = false;
			for (size_t j = 0; j < i; ++j) {
				if (!strcmp(paths->items[i], paths->items[j])) {
					duplicate = true;
				}
			}
			if (duplicate) {
				continue;
			}
			CK_FUNCTION_LIST* module = p11_kit_module_load(paths->items[i], 0);
			if (!module) {
				context_free(impl);
				return LIBSSIG_ERROR_MODULES;
			}
			if (p11_kit_module_initialize(module) != CKR_OK) {
				p11_kit_module_release(module);
				context_free(impl);
				return LIBSSIG_ERROR_MODULES;
			}
			impl->modules[count++] = module;
		}
	}
	ctx->impl = impl;
	return LIBSSIG_OK;
}

libssig_status libssig_context_open(libssig_context* ctx) {
	return libssig_context_open_modules(ctx, NULL);
}

libssig_status libssig_context_add_provider(
    libssig_context*  ctx,
    CK_FUNCTION_LIST* provider
) {
	if (!ctx || !ctx->impl || !provider || !provider->C_GetInfo ||
	    !provider->C_GetSlotList) {
		return LIBSSIG_ERROR_ARGUMENT;
	}
	struct libssig_context_impl* impl = ctx->impl;
	size_t                       count = 0;
	while (impl->modules && impl->modules[count]) {
		if (impl->modules[count] == provider) {
			return LIBSSIG_OK;
		}
		++count;
	}
	if (count > SIZE_MAX / sizeof(*impl->modules) - 2) {
		return LIBSSIG_ERROR_MEMORY;
	}
	CK_FUNCTION_LIST** combined = calloc(count + 2, sizeof(*combined));
	if (!combined) {
		return LIBSSIG_ERROR_MEMORY;
	}
	if (count) {
		memcpy(combined, impl->modules, count * sizeof(*combined));
	}
	combined[count] = provider;
	if (!impl->managed_modules) {
		impl->managed_modules = impl->modules;
		impl->managed_count = count;
	} else {
		free(impl->modules);
	}
	impl->modules = combined;
	return LIBSSIG_OK;
}

void libssig_context_close(libssig_context* ctx) {
	if (!ctx || !ctx->impl) {
		return;
	}
	context_free(ctx->impl);
	ctx->impl = NULL;
}

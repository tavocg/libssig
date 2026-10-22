/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <libssig/context.h>
#include <p11-kit/p11-kit.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(expr)                                                            \
	do {                                                                       \
		if (!(expr)) {                                                         \
			fprintf(stderr, "Failed: %s:%d: %s\n", __FILE__, __LINE__, #expr); \
			abort();                                                           \
		}                                                                      \
	} while (0)

static CK_FUNCTION_LIST  modules[2];
static CK_FUNCTION_LIST* automatic[] = {&modules[0], NULL};
static int         loads, initializes, finalizes, releases, discovers, closes;
static const char* fail_load;
static bool        fail_init;

CK_FUNCTION_LIST** p11_kit_modules_load_and_initialize(int flags) {
	(void)flags;
	++discovers;
	return automatic;
}
void p11_kit_modules_finalize_and_release(CK_FUNCTION_LIST** list) {
	CHECK(list == automatic);
	++closes;
}
CK_FUNCTION_LIST* p11_kit_module_load(const char* path, int flags) {
	(void)flags;
	++loads;
	if (fail_load && !strcmp(path, fail_load)) {
		return NULL;
	}
	return !strcmp(path, "first") ? &modules[0] : &modules[1];
}
CK_RV p11_kit_module_initialize(CK_FUNCTION_LIST* module) {
	++initializes;
	return fail_init && module == &modules[1] ? CKR_GENERAL_ERROR : CKR_OK;
}
CK_RV p11_kit_module_finalize(CK_FUNCTION_LIST* module) {
	(void)module;
	++finalizes;
	return CKR_OK;
}
void p11_kit_module_release(CK_FUNCTION_LIST* module) {
	(void)module;
	++releases;
}
static void reset(void) {
	loads = initializes = finalizes = releases = discovers = closes = 0;
	fail_load = NULL;
	fail_init = false;
}
int main(void) {
	libssig_context     ctx = {0};
	const char*         names[] = {"first", "second", "first"};
	libssig_string_list paths = {.items = names, .count = 3};
	CHECK(libssig_context_open_modules(NULL, &paths) == LIBSSIG_ERROR_ARGUMENT);
	libssig_string_list invalid = {.count = 1};
	CHECK(
	    libssig_context_open_modules(&ctx, &invalid) == LIBSSIG_ERROR_ARGUMENT
	);
	const char* bad[] = {NULL, ""};
	invalid.items = bad;
	CHECK(
	    libssig_context_open_modules(&ctx, &invalid) == LIBSSIG_ERROR_ARGUMENT
	);
	invalid.items = bad + 1;
	CHECK(
	    libssig_context_open_modules(&ctx, &invalid) == LIBSSIG_ERROR_ARGUMENT
	);
	invalid.count = SIZE_MAX;
	CHECK(libssig_context_open_modules(&ctx, &invalid) == LIBSSIG_ERROR_MEMORY);
	CHECK(!ctx.impl && !loads && !discovers);

	CHECK(libssig_context_open(&ctx) == LIBSSIG_OK);
	CHECK(discovers == 1 && !loads);
	CHECK(libssig_context_open_modules(&ctx, &paths) == LIBSSIG_ERROR_ARGUMENT);
	libssig_context_close(&ctx);
	CHECK(closes == 1 && !ctx.impl);
	libssig_string_list empty = {0};
	CHECK(libssig_context_open_modules(&ctx, &empty) == LIBSSIG_OK);
	libssig_context_close(&ctx);
	CHECK(discovers == 2 && closes == 2);

	reset();
	CHECK(libssig_context_open_modules(&ctx, &paths) == LIBSSIG_OK);
	CHECK(loads == 2 && initializes == 2 && !discovers);
	libssig_context_close(&ctx);
	libssig_context_close(&ctx);
	libssig_context_close(NULL);
	CHECK(finalizes == 2 && releases == 2 && !ctx.impl && !closes);

	reset();
	fail_load = "first";
	CHECK(libssig_context_open_modules(&ctx, &paths) == LIBSSIG_ERROR_MODULES);
	CHECK(loads == 1 && !initializes && !releases && !ctx.impl);
	reset();
	fail_load = "second";
	CHECK(libssig_context_open_modules(&ctx, &paths) == LIBSSIG_ERROR_MODULES);
	CHECK(
	    loads == 2 && initializes == 1 && finalizes == 1 && releases == 1 &&
	    !ctx.impl
	);
	reset();
	fail_init = true;
	CHECK(libssig_context_open_modules(&ctx, &paths) == LIBSSIG_ERROR_MODULES);
	CHECK(
	    loads == 2 && initializes == 2 && finalizes == 1 && releases == 2 &&
	    !ctx.impl
	);
	fail_init = false;
	CHECK(libssig_context_open_modules(&ctx, &paths) == LIBSSIG_OK);
	libssig_context_close(&ctx);
	CHECK(finalizes == 3 && releases == 4);
	return 0;
}

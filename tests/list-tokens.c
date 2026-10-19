/*
 * This file is part of libssig.
 * Copyright (C) 2026 Gustavo Calvo <tavo@tavo.cr>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <libssig/libssig.h>
#include <stdio.h>

int main(void) {
	libssig_tokens tokens = {0};
	libssig_status status = libssig_list_tokens(&tokens, true);

	if (status != LIBSSIG_OK) {
		fprintf(stderr, "Error: %d, CK_RV: 0x%lx\n", status, tokens.ck_rv);
		libssig_tokens_free(&tokens);
		return 1;
	}

	printf("Tokens: %zu\n", tokens.count);
	for (size_t i = 0; i < tokens.count; ++i) {
		printf("%s\n  URI: %s\n", tokens.items[i].label, tokens.items[i].uri);
	}

	libssig_tokens_free(&tokens);
	return 0;
}

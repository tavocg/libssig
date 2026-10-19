/*
 * This file is part of libssig.
 * Copyright (C) 2026 Gustavo Calvo <tavo@tavo.cr>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <libssig/libssig.h>
#include <p11-kit/p11-kit.h>
#include <stdio.h>

static void print_json_string(const char* text) {
	putchar('"');
	for (const unsigned char* p = (const unsigned char*)text; *p; ++p) {
		switch (*p) {
		case '"':
			fputs("\\\"", stdout);
			break;
		case '\\':
			fputs("\\\\", stdout);
			break;
		default:
			if (*p < 0x20) {
				printf("\\u%04x", (unsigned)*p);
			} else {
				putchar(*p);
			}
		}
	}
	putchar('"');
}

static void print_string_field(const char* name, const char* value) {
	printf("      \"%s\": ", name);
	print_json_string(value);
	puts(",");
}

static void print_flags(unsigned long flags) {
	static const struct {
		unsigned long value;
		const char*   name;
	} names[] = {
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
	printf("      \"flags\": %lu,\n      \"flag_names\": [", flags);
	bool first = true;
	for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
		if (flags & names[i].value) {
			if (!first) {
				fputs(", ", stdout);
			}
			print_json_string(names[i].name);
			first = false;
		}
	}
	puts("],");
}

/* null = información no disponible; -1 = límite sin cota. */
static void print_value(const char* name, unsigned long value, bool limit) {
	printf("      \"%s\": ", name);
	if (value == CK_UNAVAILABLE_INFORMATION) {
		fputs("null", stdout);
	} else if (limit && value == CK_EFFECTIVELY_INFINITE) {
		fputs("-1", stdout);
	} else {
		printf("%lu", value);
	}
}

static void print_token(const libssig_token* token) {
	puts("    {");
	print_string_field("uri", token->uri);
	print_string_field("label", token->label);
	print_string_field("manufacturer", token->manufacturer);
	print_string_field("model", token->model);
	print_string_field("serial", token->serial);
	print_flags(token->flags);
	printf(
	    "      \"hardware_version\": {\"major\": %u, \"minor\": %u},\n",
	    (unsigned)token->hardware_version.major,
	    (unsigned)token->hardware_version.minor
	);
	printf(
	    "      \"firmware_version\": {\"major\": %u, \"minor\": %u},\n",
	    (unsigned)token->firmware_version.major,
	    (unsigned)token->firmware_version.minor
	);
	fputs("      \"utc_time\": ", stdout);
	if (token->utc_time[0]) {
		print_json_string(token->utc_time);
	} else {
		fputs("null", stdout);
	}
	puts(",");
	print_value("max_session_count", token->max_session_count, true);
	puts(",");
	print_value("session_count", token->session_count, false);
	puts(",");
	print_value("max_rw_session_count", token->max_rw_session_count, true);
	puts(",");
	print_value("rw_session_count", token->rw_session_count, false);
	puts(",");
	print_value("max_pin_len", token->max_pin_len, false);
	puts(",");
	print_value("min_pin_len", token->min_pin_len, false);
	puts(",");
	print_value("total_public_memory", token->total_public_memory, false);
	puts(",");
	print_value("free_public_memory", token->free_public_memory, false);
	puts(",");
	print_value("total_private_memory", token->total_private_memory, false);
	puts(",");
	print_value("free_private_memory", token->free_private_memory, false);
	puts("");
	fputs("    }", stdout);
}

int main(void) {
	libssig_tokens tokens = {0};
	libssig_status status = libssig_list_tokens(&tokens, true);

	if (status != LIBSSIG_OK) {
		printf(
		    "{\"error\": {\"status\": %d, \"ck_rv\": %lu}}\n",
		    (int)status,
		    tokens.ck_rv
		);
		libssig_tokens_free(&tokens);
		return 1;
	}

	printf("{\n  \"count\": %zu,\n  \"tokens\": [\n", tokens.count);
	for (size_t i = 0; i < tokens.count; ++i) {
		print_token(&tokens.items[i]);
		puts(i + 1 < tokens.count ? "," : "");
	}

	puts("  ]\n}");
	libssig_tokens_free(&tokens);
	return 0;
}

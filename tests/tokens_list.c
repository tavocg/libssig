/*
 * This file is part of libssig.
 * Copyright (C) 2026 Gustavo Calvo <tavo@tavo.cr>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <libssig/libssig.h>
#include <p11-kit/p11-kit.h>
#include <stdio.h>
#include <string.h>

static void json_text_print(const char* text, size_t len) {
	putchar('"');
	for (size_t i = 0; i < len; ++i) {
		const unsigned char* p = (const unsigned char*)text + i;
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

static void json_string_print(const char* text) {
	json_text_print(text, strlen(text));
}

static void string_field_print(const char* name, const char* value) {
	printf("      \"%s\": ", name);
	json_string_print(value);
	puts(",");
}

static void flags_print(unsigned long flags, const libssig_string_list* names) {
	printf("      \"flags\": %lu,\n      \"flag_names\": [", flags);
	for (size_t i = 0; i < names->count; ++i) {
		if (i) {
			fputs(", ", stdout);
		}
		json_string_print(names->items[i]);
	}
	puts("],");
}

/* null = información no disponible; -1 = límite sin cota. */
static void value_print(const char* name, unsigned long value, bool limit) {
	printf("      \"%s\": ", name);
	if (value == CK_UNAVAILABLE_INFORMATION) {
		fputs("null", stdout);
	} else if (limit && value == CK_EFFECTIVELY_INFINITE) {
		fputs("-1", stdout);
	} else {
		printf("%lu", value);
	}
}

static void hex_print(const unsigned char* data, size_t len) {
	if (!data) {
		fputs("null", stdout);
		return;
	}
	putchar('"');
	for (size_t i = 0; i < len; ++i) {
		printf("%02x", (unsigned)data[i]);
	}
	putchar('"');
}

static void certificates_print(const libssig_certificate_list* certs) {
	fputs("      \"certificates\": [", stdout);
	for (size_t i = 0; i < certs->count; ++i) {
		const libssig_certificate* cert = &certs->items[i];
		if (i) {
			fputs(",", stdout);
		}
		fputs("\n        {\"id_hex\": ", stdout);
		hex_print(cert->id, cert->id_len);
		printf(", \"id_len\": %zu, \"label\": ", cert->id_len);
		if (cert->label) {
			json_text_print(cert->label, cert->label_len);
		} else {
			fputs("null", stdout);
		}
		printf(", \"label_len\": %zu, \"der_hex\": ", cert->label_len);
		hex_print(cert->der, cert->der_len);
		printf(", \"der_len\": %zu}", cert->der_len);
	}
	puts("]");
}

static void token_print(
    const libssig_token*            token,
    const libssig_certificate_list* certs
) {
	puts("    {");
	string_field_print("uri", token->uri);
	string_field_print("label", token->label);
	string_field_print("manufacturer", token->manufacturer);
	string_field_print("model", token->model);
	string_field_print("serial", token->serial);
	flags_print(token->flags, &token->flag_names);
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
		json_string_print(token->utc_time);
	} else {
		fputs("null", stdout);
	}
	puts(",");
	value_print("max_session_count", token->max_session_count, true);
	puts(",");
	value_print("session_count", token->session_count, false);
	puts(",");
	value_print("max_rw_session_count", token->max_rw_session_count, true);
	puts(",");
	value_print("rw_session_count", token->rw_session_count, false);
	puts(",");
	value_print("max_pin_len", token->max_pin_len, false);
	puts(",");
	value_print("min_pin_len", token->min_pin_len, false);
	puts(",");
	value_print("total_public_memory", token->total_public_memory, false);
	puts(",");
	value_print("free_public_memory", token->free_public_memory, false);
	puts(",");
	value_print("total_private_memory", token->total_private_memory, false);
	puts(",");
	value_print("free_private_memory", token->free_private_memory, false);
	puts(",");
	certificates_print(certs);
	fputs("    }", stdout);
}

int main(void) {
	libssig_context ctx = {0};
	libssig_status  status = libssig_context_open(&ctx);
	if (status != LIBSSIG_OK) {
		fprintf(stderr, "Cargar módulos: status=%d\n", (int)status);
		return 1;
	}
	libssig_token_list tokens = {0};
	status = libssig_tokens(&ctx, &tokens, true);

	if (status != LIBSSIG_OK) {
		printf(
		    "{\"error\": {\"status\": %d, \"ck_rv\": %lu}}\n",
		    (int)status,
		    tokens.ck_rv
		);
		libssig_tokens_free(&tokens);
		libssig_context_close(&ctx);
		return 1;
	}

	printf("{\n  \"count\": %zu,\n  \"tokens\": [\n", tokens.count);
	for (size_t i = 0; i < tokens.count; ++i) {
		libssig_certificate_list certs = {0};
		status = libssig_certificates(&ctx, &tokens.items[i], &certs);
		if (status != LIBSSIG_OK) {
			fprintf(
			    stderr,
			    "Certificados: status=%d, CK_RV=0x%lx\n",
			    (int)status,
			    certs.ck_rv
			);
			libssig_certificates_free(&certs);
			libssig_tokens_free(&tokens);
			libssig_context_close(&ctx);
			return 1;
		}
		token_print(&tokens.items[i], &certs);
		libssig_certificates_free(&certs);
		puts(i + 1 < tokens.count ? "," : "");
	}

	puts("  ]\n}");
	libssig_tokens_free(&tokens);
	libssig_context_close(&ctx);
	return 0;
}

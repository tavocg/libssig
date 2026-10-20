/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <libssig/internal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(expr)                                                            \
	do {                                                                       \
		if (!(expr)) {                                                         \
			fprintf(stderr, "Failed: %s:%d: %s\n", __FILE__, __LINE__, #expr); \
			return 1;                                                          \
		}                                                                      \
	} while (0)

static int type_check(
    const unsigned char* data,
    size_t               len,
    const char*          expected
) {
	char* type = NULL;
	CHECK(libssig_mime_type_detect(data, len, &type) == LIBSSIG_OK);
	CHECK(type && !strcmp(type, expected));
	free(type);
	return 0;
}

int main(int argc, char** argv) {
	const unsigned char text[] = "Prueba de texto para libmagic.\n";
	char*               type = NULL;
	if (argc == 2 && !strcmp(argv[1], "--missing-db")) {
		CHECK(
		    libssig_mime_type_detect(text, sizeof(text) - 1, &type) ==
		    LIBSSIG_ERROR_MAGIC
		);
		CHECK(!type);
		return 0;
	}

	const unsigned char
	    pdf[] = "%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n";
	const unsigned char binary[] = {0, 0xff, 42};
	CHECK(type_check(text, sizeof(text) - 1, "text/plain") == 0);
	CHECK(type_check(pdf, sizeof(pdf) - 1, "application/pdf") == 0);
	CHECK(type_check(binary, sizeof(binary), "application/octet-stream") == 0);
	CHECK(type_check(NULL, 0, "application/x-empty") == 0);
	CHECK(libssig_mime_type_detect(NULL, 1, &type) == LIBSSIG_ERROR_ARGUMENT);
	CHECK(!type);
	CHECK(
	    libssig_mime_type_detect(text, sizeof(text) - 1, NULL) ==
	    LIBSSIG_ERROR_ARGUMENT
	);
	return 0;
}

/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "mime.h"
#include <magic.h>
#include <stdlib.h>
#include <string.h>

static libssig_status mime_copy(
    magic_t     magic,
    const void* data,
    size_t      len,
    char**      out_type
) {
	const char* type = magic_buffer(magic, data, len);
	if (!type) {
		return LIBSSIG_ERROR_MAGIC;
	}

	size_t type_len = strlen(type);
	if (!type_len || type_len > 255 || !strchr(type, '/')) {
		return LIBSSIG_ERROR_MAGIC;
	}

	char* copy = malloc(type_len + 1);
	if (!copy) {
		return LIBSSIG_ERROR_MEMORY;
	}

	memcpy(copy, type, type_len + 1);
	*out_type = copy;
	return LIBSSIG_OK;
}

libssig_status libssig_mime_type_detect(
    const unsigned char* data,
    size_t               len,
    char**               out_type
) {
	if (!out_type) {
		return LIBSSIG_ERROR_ARGUMENT;
	}

	*out_type = NULL;
	if (!data && len) {
		return LIBSSIG_ERROR_ARGUMENT;
	}

	magic_t magic = magic_open(MAGIC_MIME_TYPE | MAGIC_ERROR);
	if (!magic) {
		return LIBSSIG_ERROR_MEMORY;
	}

	const unsigned char empty = 0;
	libssig_status
	    status = magic_load(magic, NULL) == 0
	                 ? mime_copy(magic, data ? data : &empty, len, out_type)
	                 : LIBSSIG_ERROR_MAGIC;
	magic_close(magic);
	return status;
}

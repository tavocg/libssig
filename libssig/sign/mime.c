/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "mime.h"
#include <magic.h>
#include <stdlib.h>
#include <string.h>
#ifdef LIBSSIG_EMBED_MAGIC_DATABASE
#include <zlib.h>
extern const unsigned char libssig_magic_data[];
extern const size_t        libssig_magic_size, libssig_magic_raw_size;
#endif

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

	unsigned char* database = NULL;
	int            loaded;
#ifdef LIBSSIG_EMBED_MAGIC_DATABASE
	/* MAGIC remains an explicit override, including its failure behavior. */
	if (!getenv("MAGIC")) {
		database = malloc(libssig_magic_raw_size);
		if (!database) {
			magic_close(magic);
			return LIBSSIG_ERROR_MEMORY;
		}
		uLongf size = (uLongf)libssig_magic_raw_size;
		int    result = uncompress(
            database,
            &size,
            libssig_magic_data,
            (uLong)libssig_magic_size
        );
		void*  buffers[] = {database};
		size_t sizes[] = {libssig_magic_raw_size};
		loaded = result == Z_OK && size == libssig_magic_raw_size
		             ? magic_load_buffers(magic, buffers, sizes, 1)
		             : -1;
	} else
#endif
	{
		loaded = magic_load(magic, NULL);
	}
	const unsigned char empty = 0;
	libssig_status      status = loaded == 0 ? mime_copy(
                                              magic,
                                              data ? data : &empty,
                                              len,
                                              out_type
                                          )
	                                         : LIBSSIG_ERROR_MAGIC;
	magic_close(magic);
	free(database); /* magic_load_buffers borrows writable, aligned memory. */
	return status;
}

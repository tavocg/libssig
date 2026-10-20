/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <libssig/libssig.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
	unsigned char* data;
	size_t         len;
} buffer;

static buffer file_read(const char* path) {
	buffer bytes = {0};
	FILE*  file = fopen(path, "rb");
	if (!file) {
		perror(path);
		return bytes;
	}
	if (fseek(file, 0, SEEK_END) == 0) {
		long len = ftell(file);
		if (len > 0 && len <= 16 * 1024 * 1024 &&
		    fseek(file, 0, SEEK_SET) == 0) {
			bytes.data = malloc((size_t)len);
			if (bytes.data &&
			    fread(bytes.data, 1, (size_t)len, file) == (size_t)len) {
				bytes.len = (size_t)len;
			}
		}
	}
	fclose(file);
	if (!bytes.len) {
		free(bytes.data);
		bytes.data = NULL;
		fprintf(stderr, "No se pudo leer %s (máximo 16 MiB).\n", path);
	}
	return bytes;
}

static bool file_write(const char* path, const libssig_signature* bytes) {
	FILE* file = fopen(path, "wbx");
	if (!file) {
		perror(path);
		return false;
	}
	bool ok = fwrite(bytes->data, 1, bytes->len, file) == bytes->len;
	if (fclose(file) != 0) {
		ok = false;
	}
	if (!ok) {
		remove(path);
	}
	return ok;
}

static libssig_status timestamp_apply(
    buffer*            files,
    libssig_signature* output
) {
	libssig_timestamp_params params = {
	    .data = files[0].data,
	    .data_len = files[0].len,
	    .request = files[1].data,
	    .request_len = files[1].len,
	    .response = files[2].data,
	    .response_len = files[2].len,
	    .ca_data = files[3].data,
	    .ca_data_len = files[3].len,
	    .intermediates_data = files[4].data,
	    .intermediates_data_len = files[4].len,
	};
	return libssig_timestamp(&params, output);
}

int main(int argc, char** argv) {
	bool request = argc == 4 && strcmp(argv[1], "request") == 0;
	bool apply = (argc == 7 || argc == 8) && strcmp(argv[1], "apply") == 0;
	if (!request && !apply) {
		fprintf(
		    stderr,
		    "Uso: %s request CADES QUERY\n"
		    "     %s apply CADES QUERY REPLY ROOTS OUTPUT [INTERMEDIATES]\n",
		    argv[0],
		    argv[0]
		);
		return EXIT_FAILURE;
	}
	buffer files[5] = {0};
	size_t count = request ? 1 : (argc == 8 ? 5 : 4);
	bool   ok = true;
	for (size_t i = 0; i < count; ++i) {
		files[i] = file_read(argv[i == 4 ? 7 : i + 2]);
		ok = ok && files[i].len != 0;
	}
	libssig_signature output = {0};
	libssig_status    status = LIBSSIG_ERROR_ARGUMENT;
	if (ok && request) {
		libssig_timestamp_request_params params = {
		    .data = files[0].data,
		    .data_len = files[0].len,
		};
		status = libssig_timestamp_request(&params, &output);
	} else if (ok) {
		status = timestamp_apply(files, &output);
	}
	ok = ok && status == LIBSSIG_OK &&
	     file_write(argv[request ? 3 : 6], &output);
	if (!ok) {
		fprintf(stderr, "Timestamp: status=%d\n", (int)status);
	}
	libssig_signature_free(&output);
	for (size_t i = 0; i < count; ++i) {
		free(files[i].data);
	}
	return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}

/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _POSIX_C_SOURCE 200809L
#include <fcntl.h>
#include <libssig/libssig.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
		if (len > 0 && len <= INT_MAX && fseek(file, 0, SEEK_SET) == 0) {
			bytes.data = malloc((size_t)len);
			if (bytes.data &&
			    fread(bytes.data, 1, (size_t)len, file) == (size_t)len &&
			    !ferror(file)) {
				bytes.len = (size_t)len;
			} else {
				free(bytes.data);
				bytes.data = NULL;
			}
		}
	}
	if (fclose(file) != 0) {
		free(bytes.data);
		bytes = (buffer){0};
	}
	if (!bytes.data) {
		fprintf(stderr, "No se pudo leer %s (1..INT_MAX bytes).\n", path);
	}
	return bytes;
}

static bool file_write(
    const char*          path,
    const unsigned char* data,
    size_t               len
) {
	int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (fd < 0) {
		perror(path);
		return false;
	}
	FILE* file = fdopen(fd, "wb");
	if (!file) {
		close(fd);
		unlink(path);
		return false;
	}
	bool ok = fwrite(data, 1, len, file) == len;
	if (fclose(file) != 0) {
		ok = false;
	}
	if (!ok) {
		unlink(path);
	}
	return ok;
}

static int request_run(char** argv, buffer* files) {
	libssig_ocsp_request_params params = {
	    .cert_data = files[0].data,
	    .cert_data_len = files[0].len,
	    .issuer_data = files[1].data,
	    .issuer_data_len = files[1].len,
	};
	libssig_ocsp_query query = {0};
	libssig_status     status = libssig_ocsp_request(&params, &query);
	bool               ok = status == LIBSSIG_OK &&
	          file_write(argv[4], query.data, query.len);
	if (status != LIBSSIG_OK) {
		fprintf(stderr, "Solicitud OCSP: status=%d\n", (int)status);
	}
	if (ok) {
		printf("Solicitud OCSP guardada (%zu bytes).\n", query.len);
		for (size_t i = 0; i < query.urls.count; ++i) {
			printf("URL: %s\n", query.urls.items[i]);
		}
	}
	libssig_ocsp_request_free(&query);
	return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int verify_run(buffer* files, unsigned int options) {
	libssig_ocsp_verify_params params = {
	    .cert_data = files[0].data,
	    .cert_data_len = files[0].len,
	    .issuer_data = files[1].data,
	    .issuer_data_len = files[1].len,
	    .request = files[2].data,
	    .request_len = files[2].len,
	    .response = files[3].data,
	    .response_len = files[3].len,
	    .ca_data = files[4].data,
	    .ca_data_len = files[4].len,
	    .intermediates_data = files[5].data,
	    .intermediates_data_len = files[5].len,
	    .options = options,
	};
	libssig_ocsp_result result = {0};
	libssig_status      status = libssig_ocsp_verify(&params, &result);
	const char*         names[] =
	    {"consulta fallida", "no revocado", "revocado", "desconocido"};
	printf(
	    "OCSP: %s (status=%d, respuesta=%d).\n",
	    names[result.status],
	    (int)status,
	    result.response_status
	);
	if (result.valid) {
		printf("thisUpdate: %s\n", result.this_update);
		if (result.next_update[0]) {
			printf("nextUpdate: %s\n", result.next_update);
		}
		if (result.status == LIBSSIG_OCSP_REVOKED) {
			printf(
			    "Revocación: %s (motivo=%d).\n",
			    result.revocation_time,
			    result.reason
			);
		}
	}
	return status == LIBSSIG_OK && result.status == LIBSSIG_OCSP_GOOD
	           ? EXIT_SUCCESS
	           : EXIT_FAILURE;
}

static void usage_print(const char* program, FILE* file) {
	fprintf(
	    file,
	    "Uso:\n  %s request CERT EMISOR SOLICITUD.der\n"
	    "  %s verify CERT EMISOR SOLICITUD.der RESPUESTA.der "
	    "RAICES|--system-trust "
	    "[INTERMEDIARIOS] [--allow-missing-nonce]\n",
	    program,
	    program
	);
}

int main(int argc, char** argv) {
	if (argc == 2 && !strcmp(argv[1], "--help")) {
		usage_print(argv[0], stdout);
		return EXIT_SUCCESS;
	}
	unsigned int options = 0;
	if (argc > 2 && !strcmp(argv[argc - 1], "--allow-missing-nonce")) {
		options |= LIBSSIG_OCSP_ALLOW_MISSING_NONCE;
		--argc;
	}
	bool request = argc == 5 && !strcmp(argv[1], "request");
	bool verify = (argc == 7 || argc == 8) && !strcmp(argv[1], "verify");
	if ((!request && !verify) || (request && options)) {
		usage_print(argv[0], stderr);
		return EXIT_FAILURE;
	}
	if (verify && !strcmp(argv[6], "--system-trust")) {
		options |= LIBSSIG_OCSP_SYSTEM_TRUST;
	}
	buffer files[6] = {0};
	size_t count = request ? 2 : (size_t)argc - 2;
	bool   ok = true;
	for (size_t i = 0; i < count; ++i) {
		if (i == 4 && (options & LIBSSIG_OCSP_SYSTEM_TRUST)) {
			continue;
		}
		files[i] = file_read(argv[i + 2]);
		if (!files[i].data) {
			ok = false;
			break;
		}
	}
	int result = ok ? (request ? request_run(argv, files)
	                           : verify_run(files, options))
	                : EXIT_FAILURE;
	for (size_t i = 0; i < count; ++i) {
		free(files[i].data);
	}
	return result;
}

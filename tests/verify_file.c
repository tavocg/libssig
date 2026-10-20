/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <libssig/libssig.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned char* file_read(const char* path, size_t* out_len) {
	FILE* file = fopen(path, "rb");
	if (!file) {
		perror(path);
		return NULL;
	}

	unsigned char* data = NULL;
	if (fseek(file, 0, SEEK_END) == 0) {
		long len = ftell(file);
		if (len >= 0 && len <= INT_MAX && fseek(file, 0, SEEK_SET) == 0) {
			data = malloc(len ? (size_t)len : 1);
			if (data && (fread(data, 1, (size_t)len, file) != (size_t)len ||
			             ferror(file))) {
				free(data);
				data = NULL;
			}
			if (data) {
				*out_len = (size_t)len;
			}
		}
	}

	if (fclose(file) != 0) {
		free(data);
		data = NULL;
	}

	if (!data) {
		fputs("No se pudo leer el archivo (máximo INT_MAX bytes).\n", stderr);
	}
	return data;
}

static const char* status_text(libssig_status status) {
	switch (status) {
	case LIBSSIG_ERROR_CONTENT_REQUIRED:
		return "La firma es separada: falta el archivo original.";
	case LIBSSIG_ERROR_VERIFY:
		return "La firma, el contenido o los atributos no son válidos.";
	case LIBSSIG_ERROR_TRUST:
		return "Firma válida; no se pudo validar la confianza de todos los "
		       "firmantes.";
	case LIBSSIG_ERROR_FORMAT:
		return "Firma CMS/CAdES o certificados PEM/DER malformados.";
	case LIBSSIG_ERROR_ARGUMENT:
		return "Argumentos inválidos; revise contenido y opciones de "
		       "confianza.";
	default:
		return "No se pudo verificar la firma.";
	}
}

static void result_print(const libssig_verify_result* result) {
	printf("Firma criptográfica válida; %zu firmante(s).\n", result->count);
	printf(
	    "Confianza: %s.\n",
	    !result->trust_checked ? "no comprobada"
	    : result->trusted      ? "válida"
	                           : "fallida"
	);
	for (size_t i = 0; i < result->count; ++i) {
		printf(
		    "Firmante %zu: certificado DER de %zu bytes",
		    i + 1,
		    result->signers[i].cert_der_len
		);
		if (result->trust_checked) {
			printf(", error X.509=%ld", result->signers[i].trust_error);
		}
		putchar('\n');
		if (result->signers[i].mime_type) {
			printf("MIME: %s\n", result->signers[i].mime_type);
		}
	}
}

static void usage_print(const char* program, FILE* output) {
	fprintf(
	    output,
	    "Uso: %s [--system-trust] [--ca-file RAICES.pem] "
	    "[--intermediates INTERMEDIARIOS.pem] FIRMA [CONTENIDO_ORIGINAL]\n",
	    program
	);
}

static int options_parse(
    int                    argc,
    char**                 argv,
    libssig_verify_params* params,
    const char**           ca_path,
    const char**           intermediates_path
) {
	int i = 1;
	while (i < argc && argv[i][0] == '-') {
		if (!strcmp(argv[i], "--")) {
			return i + 1;
		}

		if (!strcmp(argv[i], "--system-trust")) {
			params->options |= LIBSSIG_VERIFY_SYSTEM_TRUST;
			++i;
			continue;
		}

		const char** path = !strcmp(argv[i], "--ca-file") ? ca_path
		                    : !strcmp(argv[i], "--intermediates")
		                        ? intermediates_path
		                        : NULL;
		if (!path || *path || i + 1 >= argc || !argv[i + 1][0] ||
		    !strncmp(argv[i + 1], "--", 2)) {
			return -1;
		}
		*path = argv[i + 1];
		i += 2;
	}
	return i;
}

static bool inputs_read(
    const char* const      paths[4],
    unsigned char*         buffers[4],
    libssig_verify_params* params
) {
	size_t* lens[] = {
	    &params->data_len,
	    &params->content_len,
	    &params->ca_data_len,
	    &params->intermediates_data_len
	};
	for (size_t i = 0; i < 4; ++i) {
		if (paths[i]) {
			buffers[i] = file_read(paths[i], lens[i]);
			if (!buffers[i]) {
				return false;
			}
		}
	}
	params->data = buffers[0];
	params->content = buffers[1];
	params->ca_data = buffers[2];
	params->intermediates_data = buffers[3];
	return true;
}

int main(int argc, char** argv) {
	if (argc == 2 && !strcmp(argv[1], "--help")) {
		usage_print(argv[0], stdout);
		return EXIT_SUCCESS;
	}

	libssig_verify_params params = {0};
	const char*           ca_path = NULL;
	const char*           intermediates_path = NULL;
	int                   first = options_parse(
        argc,
        argv,
        &params,
        &ca_path,
        &intermediates_path
    );
	if (first < 0 || argc < first + 1 || argc > first + 2 ||
	    (intermediates_path && !ca_path &&
	     !(params.options & LIBSSIG_VERIFY_SYSTEM_TRUST))) {
		usage_print(argv[0], stderr);
		return EXIT_FAILURE;
	}

	const char* paths[] = {
	    argv[first],
	    argc == first + 2 ? argv[first + 1] : NULL,
	    ca_path,
	    intermediates_path
	};
	unsigned char*        buffers[4] = {0};
	libssig_verify_result result = {0};
	libssig_status        status = LIBSSIG_ERROR_ARGUMENT;
	if (inputs_read(paths, buffers, &params)) {
		status = libssig_verify(&params, &result);
		if (result.signature_valid) {
			result_print(&result);
		}

		if (status != LIBSSIG_OK) {
			fprintf(
			    stderr,
			    "%s (status=%d)\n",
			    status_text(status),
			    (int)status
			);
		}
	}
	libssig_verify_free(&result);
	for (size_t i = 0; i < 4; ++i) {
		free(buffers[i]);
	}
	return status == LIBSSIG_OK ? EXIT_SUCCESS : EXIT_FAILURE;
}

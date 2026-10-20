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
		return "El archivo no es un contenedor CMS/CAdES DER válido.";
	case LIBSSIG_ERROR_ARGUMENT:
		return "Argumentos inválidos; no proporcione contenido externo para "
		       "una firma attached.";
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

int main(int argc, char** argv) {
	bool         help = argc == 2 && !strcmp(argv[1], "--help");
	unsigned int options = 0;
	int          first = 1;
	if (argc > 1 && !strcmp(argv[1], "--system-trust")) {
		options = LIBSSIG_VERIFY_SYSTEM_TRUST;
		++first;
	}

	if (help || argc < first + 1 || argc > first + 2) {
		fprintf(
		    help ? stdout : stderr,
		    "Uso: %s [--system-trust] FIRMA [CONTENIDO_ORIGINAL]\n",
		    argv[0]
		);
		return help ? EXIT_SUCCESS : EXIT_FAILURE;
	}

	libssig_verify_params params = {.options = options};
	unsigned char*        data = file_read(argv[first], &params.data_len);
	if (!data) {
		return EXIT_FAILURE;
	}

	unsigned char* content = argc == first + 2 ? file_read(
	                                                 argv[first + 1],
	                                                 &params.content_len
	                                             )
	                                           : NULL;
	if (argc == first + 2 && !content) {
		free(data);
		return EXIT_FAILURE;
	}
	params.data = data;
	params.content = content;

	libssig_verify_result result = {0};
	libssig_status        status = libssig_verify(&params, &result);
	if (result.signature_valid) {
		result_print(&result);
	}

	if (status != LIBSSIG_OK) {
		fprintf(stderr, "%s (status=%d)\n", status_text(status), (int)status);
	}
	libssig_verify_free(&result);
	free(content);
	free(data);
	return status == LIBSSIG_OK ? EXIT_SUCCESS : EXIT_FAILURE;
}

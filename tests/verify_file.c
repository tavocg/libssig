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
		       "firmantes o TSA.";
	case LIBSSIG_ERROR_REVOKED:
		return "Un certificado está revocado.";
	case LIBSSIG_ERROR_EVIDENCE:
		return "Evidencia histórica ausente, incompleta o no utilizable.";
	case LIBSSIG_ERROR_OCSP:
		return "OCSP no pudo establecer un estado no revocado.";
	case LIBSSIG_ERROR_TIMESTAMP:
		return "Sello de tiempo inválido o ausente cuando se exige.";
	case LIBSSIG_ERROR_FORMAT:
		return "Firma CMS/CAdES o certificados PEM/DER malformados.";
	case LIBSSIG_ERROR_ARGUMENT:
		return "Argumentos inválidos; revise contenido y opciones de "
		       "confianza.";
	default:
		return "No se pudo verificar la firma.";
	}
}

static void ocsp_print(const char* target, const libssig_ocsp_result* result) {
	if (result->error == LIBSSIG_ERROR_NOT_FOUND) {
		return;
	}
	const char* names[] =
	    {"consulta fallida", "no revocado", "revocado", "desconocido"};
	printf(
	    "OCSP %s: %s (error=%d).\n",
	    target,
	    names[result->status],
	    (int)result->error
	);
}

static void timestamp_print(const libssig_verify_timestamp* stamp) {
	if (!stamp->present) {
		puts("Sello: ausente.");
		return;
	}

	printf(
	    "Sello: %s (status=%d).\n",
	    stamp->valid ? "válido" : "inválido",
	    (int)stamp->status
	);
	if (stamp->valid) {
		printf("Fecha del sello: %s\n", stamp->time);
	}
	printf(
	    "Confianza TSA: %s",
	    !stamp->trust_checked ? "no comprobada"
	    : stamp->trusted      ? "válida"
	                          : "fallida"
	);
	if (stamp->trust_checked) {
		printf(" (error X.509=%ld)", stamp->trust_error);
	}
	puts(".");
	ocsp_print("TSA", &stamp->ocsp);
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
		if (result->signers[i].level_detected) {
			const char* levels[] = {"B-LTA", "B-B", "B-T", "B-LT"};
			printf(
			    "Nivel: %s (%s).\n",
			    levels[result->signers[i].level],
			    result->signers[i].level_validated ? "validado" : "no validado"
			);
		}
		ocsp_print("firmante", &result->signers[i].ocsp);
		timestamp_print(&result->signers[i].timestamp);
		if (result->signers[i].history != LIBSSIG_HISTORY_NOT_CHECKED) {
			const char* states[] = {
			    "no comprobada",
			    "válida",
			    "incompleta",
			    "revocado",
			    "sin confianza"
			};
			printf(
			    "Validación histórica: %s; fecha: %s.\n",
			    states[result->signers[i].history],
			    result->signers[i].validation_time
			);
		}
	}
}

static void usage_print(const char* program, FILE* output) {
	fprintf(
	    output,
	    "Uso: %s [--system-trust] [--ca-file RAICES.pem] "
	    "[--intermediates INTERMEDIARIOS.pem] [--require-timestamp] "
	    "[--historical] "
	    "[--tsa-system-trust] [--tsa-ca-file RAICES.pem] "
	    "[--tsa-intermediates INTERMEDIARIOS.pem] FIRMA [CONTENIDO_ORIGINAL]\n",
	    program
	);
}

static unsigned int option_flag(const char* arg) {
	if (!strcmp(arg, "--historical")) {
		return LIBSSIG_VERIFY_HISTORICAL;
	}

	if (!strcmp(arg, "--system-trust")) {
		return LIBSSIG_VERIFY_SYSTEM_TRUST;
	}

	if (!strcmp(arg, "--tsa-system-trust")) {
		return LIBSSIG_VERIFY_TSA_SYSTEM_TRUST;
	}

	return !strcmp(arg, "--require-timestamp")
	           ? LIBSSIG_VERIFY_REQUIRE_TIMESTAMP
	           : 0;
}

static int options_parse(
    int                    argc,
    char**                 argv,
    libssig_verify_params* params,
    const char*            paths[4]
) {
	const char* names[] = {
	    "--ca-file",
	    "--intermediates",
	    "--tsa-ca-file",
	    "--tsa-intermediates"
	};
	int i = 1;
	while (i < argc && argv[i][0] == '-') {
		if (!strcmp(argv[i], "--")) {
			return i + 1;
		}

		unsigned int flag = option_flag(argv[i]);
		if (flag) {
			params->options |= flag;
			++i;
			continue;
		}

		size_t j = 0;
		while (j < 4 && strcmp(argv[i], names[j])) {
			++j;
		}

		if (j == 4 || paths[j] || i + 1 >= argc || !argv[i + 1][0] ||
		    !strncmp(argv[i + 1], "--", 2)) {
			return -1;
		}
		paths[j] = argv[i + 1];
		i += 2;
	}
	return i;
}

static bool inputs_read(
    const char* const      paths[6],
    unsigned char*         buffers[6],
    libssig_verify_params* params
) {
	size_t* lens[] = {
	    &params->data_len,
	    &params->content_len,
	    &params->ca_data_len,
	    &params->intermediates_data_len,
	    &params->tsa_ca_data_len,
	    &params->tsa_intermediates_data_len,
	};
	for (size_t i = 0; i < 6; ++i) {
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
	params->tsa_ca_data = buffers[4];
	params->tsa_intermediates_data = buffers[5];
	return true;
}

int main(int argc, char** argv) {
	if (argc == 2 && !strcmp(argv[1], "--help")) {
		usage_print(argv[0], stdout);
		return EXIT_SUCCESS;
	}

	libssig_verify_params params = {0};
	const char*           cert_paths[4] = {0};
	int first = options_parse(argc, argv, &params, cert_paths);
	if (first < 0 || argc < first + 1 || argc > first + 2 ||
	    (cert_paths[1] && !cert_paths[0] &&
	     !(params.options & LIBSSIG_VERIFY_SYSTEM_TRUST)) ||
	    (cert_paths[3] && !cert_paths[2] &&
	     !(params.options & LIBSSIG_VERIFY_TSA_SYSTEM_TRUST))) {
		usage_print(argv[0], stderr);
		return EXIT_FAILURE;
	}

	const char* paths[] = {
	    argv[first],
	    argc == first + 2 ? argv[first + 1] : NULL,
	    cert_paths[0],
	    cert_paths[1],
	    cert_paths[2],
	    cert_paths[3]
	};
	unsigned char*        buffers[6] = {0};
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
	for (size_t i = 0; i < 6; ++i) {
		free(buffers[i]);
	}
	return status == LIBSSIG_OK ? EXIT_SUCCESS : EXIT_FAILURE;
}

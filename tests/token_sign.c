/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <errno.h>
#include <fcntl.h>
#include <libssig/internal.h>
#include <limits.h>
#include <openssl/crypto.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

static const unsigned char message[] = "libssig: prueba de firma con token.\n";

static void error_print(
    const char*    operation,
    libssig_status status,
    unsigned long  rv
) {
	fprintf(
	    stderr,
	    "%s: status=%d, CK_RV=0x%lx (%s)\n",
	    operation,
	    (int)status,
	    rv,
	    p11_kit_strerror(rv)
	);
}

static void usage_print(const char* program) {
#ifdef LIBSSIG_CMS_FILE
	fprintf(
	    stderr,
	    "Uso: %s URI ID_HEX INPUT OUTPUT.p7s [rsa-pkcs|rsa-pss|ecdsa] "
	    "[sha256|sha384|sha512]\n",
	    program
	);
#else
	fprintf(
	    stderr,
	    "Uso: %s URI ID_HEX [rsa-pkcs|rsa-pss|ecdsa] [sha256|sha384|sha512]\n",
	    program
	);
#endif
	fputs("Por defecto: rsa-pkcs y sha256. ID_HEX sin separadores.\n", stderr);
}

static int hex_digit(char value) {
	if (value >= '0' && value <= '9') {
		return value - '0';
	}
	if (value >= 'a' && value <= 'f') {
		return value - 'a' + 10;
	}
	if (value >= 'A' && value <= 'F') {
		return value - 'A' + 10;
	}
	return -1;
}

static unsigned char* id_parse(const char* text, size_t* out_len) {
	size_t len = strlen(text);
	if (!len || len % 2) {
		return NULL;
	}

	unsigned char* id = malloc(len / 2);
	if (!id) {
		return NULL;
	}

	for (size_t i = 0; i < len; i += 2) {
		int high = hex_digit(text[i]), low = hex_digit(text[i + 1]);
		if (high < 0 || low < 0) {
			free(id);
			return NULL;
		}
		id[i / 2] = (unsigned char)((high << 4) | low);
	}
	*out_len = len / 2;
	return id;
}

static bool options_parse(int argc, char** argv, libssig_sign_params* params) {
	const char* algorithms[] = {"rsa-pkcs", "rsa-pss", "ecdsa"};
	const char* hashes[] = {"sha256", "sha384", "sha512"};
#ifdef LIBSSIG_CMS_FILE
	const int first = 5;
#else
	const int first = 3;
#endif
	if (argc < first || argc > first + 2) {
		return false;
	}

	if (argc > first) {
		size_t i = 0;
		while (i < 3 && strcasecmp(argv[first], algorithms[i])) {
			++i;
		}
		if (i == 3) {
			return false;
		}
		params->algo = (libssig_algo)i;
	}

	if (argc > first + 1) {
		size_t i = 0;
		while (i < 3 && strcasecmp(argv[first + 1], hashes[i])) {
			++i;
		}
		if (i == 3) {
			return false;
		}
		params->hash = (libssig_hash)i;
	}
	return true;
}

static const libssig_certificate* certificate_find(
    const libssig_certificate_list* certs,
    const libssig_sign_params*      params
) {
	const libssig_certificate* match = NULL;
	for (size_t i = 0; i < certs->count; ++i) {
		const libssig_certificate* cert = &certs->items[i];
		if (!cert->id || cert->id_len != params->id_len ||
		    memcmp(cert->id, params->id, params->id_len)) {
			continue;
		}

		if (match) {
			fputs("Más de un certificado coincide con ID_HEX.\n", stderr);
			return NULL;
		}
		match = cert;
	}

	if (!match) {
		fputs("No se encontró un certificado con ese ID.\n", stderr);
	}
	return match;
}

static EVP_PKEY* certificate_key_get(const libssig_certificate* cert) {
	if (!cert->der || !cert->der_len || cert->der_len > LONG_MAX) {
		fputs("El certificado no contiene DER accesible.\n", stderr);
		return NULL;
	}

	const unsigned char* cursor = cert->der;
	X509*                x509 = d2i_X509(NULL, &cursor, (long)cert->der_len);
	if (!x509 || cursor != cert->der + cert->der_len) {
		X509_free(x509);
		fputs("Certificado X.509 inválido.\n", stderr);
		return NULL;
	}

	EVP_PKEY* key = X509_get_pubkey(x509);
	X509_free(x509);
	return key;
}

static bool pin_read(
    const libssig_context* ctx,
    libssig_sign_params*   params,
    char*                  pin,
    size_t                 capacity
) {
	libssig_session s = {0};
	CK_RV           rv = CKR_OK;
	libssig_status
	    status = libssig_session_open(ctx, params->token->uri, &s, &rv);
	if (status != LIBSSIG_OK) {
		error_print("Abrir sesión para consultar autenticación", status, rv);
		return false;
	}

	CK_TOKEN_INFO token_info;
	rv = s.module->C_GetTokenInfo(s.slot, &token_info);
	CK_RV close_rv = libssig_session_close(&s);
	if (rv != CKR_OK || close_rv != CKR_OK) {
		error_print(
		    "Consultar autenticación",
		    LIBSSIG_ERROR_PKCS11,
		    rv != CKR_OK ? rv : close_rv
		);
		return false;
	}

	if (token_info.flags & CKF_PROTECTED_AUTHENTICATION_PATH) {
		puts("Completá la autenticación en el dispositivo cuando se solicite.");
		return true;
	}

	if (!(token_info.flags & CKF_LOGIN_REQUIRED)) {
		return true;
	}

	if (!isatty(STDIN_FILENO) ||
	    EVP_read_pw_string(pin, (int)capacity, "PIN: ", 0) != 0) {
		fputs(
		    "No se pudo leer el PIN; se requiere una terminal interactiva.\n",
		    stderr
		);
		return false;
	}
	params->pin = (const unsigned char*)pin;
	params->pin_len = strlen(pin);
	return true;
}

static unsigned char* ecdsa_der(
    const libssig_signature* signature,
    size_t*                  out_len
) {
	if (!signature->len || signature->len % 2 || signature->len / 2 > INT_MAX) {
		return NULL;
	}

	int        half = (int)(signature->len / 2);
	BIGNUM*    r = BN_bin2bn(signature->data, half, NULL);
	BIGNUM*    s = BN_bin2bn(signature->data + half, half, NULL);
	ECDSA_SIG* sig = ECDSA_SIG_new();
	if (!r || !s || !sig || ECDSA_SIG_set0(sig, r, s) != 1) {
		BN_free(r);
		BN_free(s);
		ECDSA_SIG_free(sig);
		return NULL;
	}

	unsigned char* der = NULL;
	int            len = i2d_ECDSA_SIG(sig, &der);
	ECDSA_SIG_free(sig);
	if (len <= 0) {
		OPENSSL_free(der);
		return NULL;
	}
	*out_len = (size_t)len;
	return der;
}

static bool verification_init(
    EVP_MD_CTX*                md,
    EVP_PKEY*                  key,
    const libssig_sign_params* params
) {
	const EVP_MD* hashes[] = {EVP_sha256(), EVP_sha384(), EVP_sha512()};
	const EVP_MD* hash = hashes[params->hash];
	EVP_PKEY_CTX* key_ctx = NULL;
	if (EVP_DigestVerifyInit(md, &key_ctx, hash, NULL, key) != 1) {
		return false;
	}

	if (params->algo == LIBSSIG_ALGO_ECDSA) {
		return EVP_PKEY_base_id(key) == EVP_PKEY_EC;
	}

	int padding = params->algo == LIBSSIG_ALGO_RSA_PSS ? RSA_PKCS1_PSS_PADDING
	                                                   : RSA_PKCS1_PADDING;
	if (EVP_PKEY_CTX_set_rsa_padding(key_ctx, padding) <= 0) {
		return false;
	}

	return params->algo != LIBSSIG_ALGO_RSA_PSS ||
	       (EVP_PKEY_CTX_set_rsa_mgf1_md(key_ctx, hash) > 0 &&
	        EVP_PKEY_CTX_set_rsa_pss_saltlen(key_ctx, EVP_MD_size(hash)) > 0);
}

static bool signature_verify(
    EVP_PKEY*                  key,
    const libssig_sign_params* params,
    const libssig_signature*   signature
) {
	size_t               len = signature->len;
	unsigned char*       der = NULL;
	const unsigned char* bytes = signature->data;
	if (params->algo == LIBSSIG_ALGO_ECDSA) {
		der = ecdsa_der(signature, &len);
		if (!der) {
			return false;
		}
		bytes = der;
	}

	EVP_MD_CTX* md = EVP_MD_CTX_new();
	bool        verified = md && verification_init(md, key, params) &&
	                EVP_DigestVerify(
	                    md,
	                    bytes,
	                    len,
	                    params->data,
	                    params->data_len
	                ) == 1;
	EVP_MD_CTX_free(md);
	OPENSSL_free(der);
	return verified;
}

static bool output_write(const char* path, const libssig_signature* output) {
	int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (fd < 0) {
		perror(path);
		return false;
	}

	size_t offset = 0;
	while (offset < output->len) {
		ssize_t len = write(fd, output->data + offset, output->len - offset);
		if (len < 0 && errno == EINTR) {
			continue;
		}
		if (len <= 0) {
			break;
		}
		offset += (size_t)len;
	}
	bool ok = close(fd) == 0 && offset == output->len;
	if (!ok) {
		fputs("No se pudo escribir la firma completa.\n", stderr);
		unlink(path);
	}
	return ok;
}

#ifdef LIBSSIG_CMS_FILE
static unsigned char* input_read(const char* path, size_t* out_len) {
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
#endif

static bool sign_and_verify(
    const libssig_context*     ctx,
    libssig_sign_params*       params,
    EVP_PKEY*                  key,
    const libssig_certificate* cert,
    const char*                output_path
) {
	char pin[1024] = {0};
	if (!pin_read(ctx, params, pin, sizeof(pin))) {
		OPENSSL_cleanse(pin, sizeof(pin));
		return false;
	}

	libssig_signature signature = {0};
	libssig_status
	    status = output_path ? libssig_cades_sign(ctx, params, cert, &signature)
	                         : libssig_session_sign(ctx, params, &signature);
	OPENSSL_cleanse(pin, sizeof(pin));
	params->pin = NULL;
	params->pin_len = 0;
	if (status != LIBSSIG_OK) {
		error_print("Firmar", status, signature.ck_rv);
		if (status == LIBSSIG_ERROR_CRYPTO) {
			ERR_print_errors_fp(stderr);
		}
		libssig_signature_free(&signature);
		return false;
	}

	bool verified = output_path ? output_write(output_path, &signature)
	                            : signature_verify(key, params, &signature);
	if (verified) {
		printf(
		    output_path
		        ? "CAdES B-B detached verificado y guardado (%zu bytes).\n"
		        : "Firma de prueba verificada correctamente (%zu bytes).\n",
		    signature.len
		);
	} else {
		fputs(
		    output_path ? "No se pudo guardar el CAdES verificado.\n"
		                : "La firma no se pudo verificar con el certificado "
		                  "seleccionado.\n",
		    stderr
		);
		ERR_print_errors_fp(stderr);
	}
	libssig_signature_free(&signature);
	return verified;
}

static bool test_run(
    const libssig_context* ctx,
    libssig_sign_params*   params,
    const char*            output_path
) {
	libssig_certificate_list certs = {0};
	libssig_status           status = libssig_certificates(
        ctx,
        params->token,
        &certs,
        LIBSSIG_CERTIFICATES_ALL
    );
	if (status != LIBSSIG_OK) {
		error_print("Listar certificados", status, certs.ck_rv);
		libssig_certificates_free(&certs);
		return false;
	}

	const libssig_certificate* cert = certificate_find(&certs, params);
	EVP_PKEY*                  key = cert ? certificate_key_get(cert) : NULL;
	bool verified = key && sign_and_verify(ctx, params, key, cert, output_path);
	EVP_PKEY_free(key);
	libssig_certificates_free(&certs);
	return verified;
}

int main(int argc, char** argv) {
	if (argc == 2 && !strcmp(argv[1], "--help")) {
		usage_print(argv[0]);
		return 0;
	}

	libssig_sign_params params = {
	    .data = message,
	    .data_len = sizeof(message) - 1
	};
	if (!options_parse(argc, argv, &params)) {
		usage_print(argv[0]);
		return 1;
	}

	unsigned char* id = id_parse(argv[2], &params.id_len);
	if (!id) {
		fputs("ID_HEX inválido o memoria insuficiente.\n", stderr);
		return 1;
	}
	const char* output_path = NULL;
#ifdef LIBSSIG_CMS_FILE
	unsigned char* input = input_read(argv[3], &params.data_len);
	if (!input) {
		free(id);
		return 1;
	}
	params.data = input;
	output_path = argv[4];
#endif
	libssig_token token = {.uri = argv[1]};
	params.token = &token;
	params.id = id;
	libssig_context ctx = {0};
	libssig_status  status = libssig_context_open(&ctx);
	bool            verified = false;
	if (status == LIBSSIG_OK) {
		verified = test_run(&ctx, &params, output_path);
	} else {
		error_print("Cargar módulos", status, CKR_OK);
	}
	libssig_context_close(&ctx);
	free(id);
#ifdef LIBSSIG_CMS_FILE
	free(input);
#endif
	return verified ? 0 : 1;
}

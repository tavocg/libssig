/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <libssig/internal.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void error_print(
    const char*    operation,
    libssig_status status,
    CK_RV          rv
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

static libssig_status token_login(libssig_session* s, CK_RV* out_rv) {
	CK_TOKEN_INFO token_info;
	*out_rv = s->module->C_GetTokenInfo(s->slot, &token_info);
	if (*out_rv != CKR_OK) {
		return LIBSSIG_ERROR_PKCS11;
	}

	if (!(token_info.flags & CKF_LOGIN_REQUIRED)) {
		puts("El token no requiere autenticación.");
		return LIBSSIG_OK;
	}

	if (token_info.flags & CKF_PROTECTED_AUTHENTICATION_PATH) {
		puts("Completá la autenticación en el dispositivo.");
		return libssig_session_login(s, NULL, 0, out_rv);
	}

	if (!isatty(STDIN_FILENO)) {
		fputs(
		    "Se necesita una terminal interactiva para ingresar el PIN.\n",
		    stderr
		);
		return LIBSSIG_ERROR_ARGUMENT;
	}

	char pin[1024] = {0};
	if (EVP_read_pw_string(pin, sizeof(pin), "PIN: ", 0) != 0) {
		OPENSSL_cleanse(pin, sizeof(pin));
		fputs("No se pudo leer el PIN.\n", stderr);
		return LIBSSIG_ERROR_ARGUMENT;
	}

	libssig_status status = libssig_session_login(
	    s,
	    (const unsigned char*)pin,
	    strlen(pin),
	    out_rv
	);
	OPENSSL_cleanse(pin, sizeof(pin));
	return status;
}

int main(int argc, char** argv) {
	if (argc != 2) {
		fprintf(stderr, "Uso: %s 'pkcs11:token=...;serial=...'\n", argv[0]);
		return 1;
	}

	libssig_context ctx = {0};
	libssig_status  status = libssig_context_open(&ctx);
	if (status != LIBSSIG_OK) {
		error_print("Cargar módulos", status, CKR_OK);
		return 1;
	}

	libssig_session s = {0};
	CK_RV           rv = CKR_OK;
	status = libssig_session_open(&ctx, argv[1], &s, &rv);
	if (status != LIBSSIG_OK) {
		error_print("Abrir sesión", status, rv);
		libssig_context_close(&ctx);
		return 1;
	}

	status = token_login(&s, &rv);
	if (status != LIBSSIG_OK) {
		error_print("Autenticar", status, rv);
	} else {
		puts("Sesión autenticada correctamente.");
	}

	CK_RV close_rv = libssig_session_close(&s);
	libssig_context_close(&ctx);
	if (close_rv != CKR_OK) {
		error_print("Cerrar sesión", LIBSSIG_ERROR_PKCS11, close_rv);
		return 1;
	}
	return status == LIBSSIG_OK ? 0 : 1;
}

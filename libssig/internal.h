/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef LIBSSIG_INTERNAL_H
#define LIBSSIG_INTERNAL_H

#include <libssig/libssig.h>
#include <p11-kit/p11-kit.h>

typedef struct {
	CK_FUNCTION_LIST** modules;
} pkcs11_context;

/* El contexto debe permanecer abierto mientras existan sesiones. */
typedef struct {
	CK_FUNCTION_LIST* module;
	CK_SLOT_ID        slot;
	CK_SESSION_HANDLE handle;
	bool              open;
} pkcs11_session;

/* Inicializar los recursos con {0}; cerrarlos antes de reutilizarlos. */
libssig_status pkcs11_context_open(pkcs11_context* ctx);
void           pkcs11_context_close(pkcs11_context* ctx);
libssig_status pkcs11_session_open(
    const pkcs11_context* ctx,
    const char*           uri,
    pkcs11_session*       s,
    CK_RV*                out_rv
);
/* No guarda el PIN. NULL, 0 solicita la ruta protegida del dispositivo.
 * Un PIN vacío explícito se pasa con un puntero no NULL y longitud cero. */
libssig_status pkcs11_session_login(
    pkcs11_session*      s,
    const unsigned char* pin,
    size_t               pin_len,
    CK_RV*               out_rv
);
CK_RV pkcs11_session_close(pkcs11_session* s);

libssig_status pkcs11_collect_certificates(
    pkcs11_session*       s,
    libssig_certificates* certs,
    CK_RV*                out_rv
);

#endif

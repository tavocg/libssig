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
CK_RV pkcs11_session_close(pkcs11_session* s);

#endif

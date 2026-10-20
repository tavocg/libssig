/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef LIBSSIG_INTERNAL_H
#define LIBSSIG_INTERNAL_H

#include <libssig/libssig.h>
#include <p11-kit/p11-kit.h>

typedef struct {
	CK_FUNCTION_LIST** modules;
} libssig_context;

/* El contexto debe permanecer abierto mientras existan sesiones. */
typedef struct {
	CK_FUNCTION_LIST* module;
	CK_SLOT_ID        slot;
	CK_SESSION_HANDLE handle;
	bool              open;
} libssig_session;

/* Inicializar los recursos con {0}; cerrarlos antes de reutilizarlos. */
libssig_status libssig_context_open(libssig_context* ctx);
void           libssig_context_close(libssig_context* ctx);
libssig_status libssig_session_open(
    const libssig_context* ctx,
    const char*            uri,
    libssig_session*       s,
    CK_RV*                 out_rv
);
/* No guarda el PIN. NULL, 0 solicita la ruta protegida del dispositivo.
 * Un PIN vacío explícito se pasa con un puntero no NULL y longitud cero. */
libssig_status libssig_session_login(
    libssig_session*     s,
    const unsigned char* pin,
    size_t               pin_len,
    CK_RV*               out_rv
);
CK_RV libssig_session_close(libssig_session* s);

libssig_status libssig_certificates_collect(
    libssig_session*          s,
    libssig_certificate_list* certs,
    CK_RV*                    out_rv
);

#endif

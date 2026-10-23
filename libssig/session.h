/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef LIBSSIG_SESSION_H
#define LIBSSIG_SESSION_H

#include <libssig/libssig.h>
#include <p11-kit/p11-kit.h>

struct libssig_context_impl {
	CK_FUNCTION_LIST** modules;
	bool               explicit_modules;
};

/* El contexto debe permanecer abierto mientras existan sesiones. */
typedef struct {
	CK_FUNCTION_LIST* module;
	CK_SLOT_ID        slot;
	CK_SESSION_HANDLE handle;
	bool              open;
} libssig_session;

/* Inicializar los recursos con {0}; cerrarlos antes de reutilizarlos. */
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

void           libssig_token_clear(libssig_token* token);
libssig_status libssig_token_from_info(
    const CK_TOKEN_INFO* info,
    libssig_token*       token
);
libssig_status libssig_attribute_read(
    libssig_session*  session,
    CK_OBJECT_HANDLE  object,
    CK_ATTRIBUTE_TYPE type,
    unsigned char**   data,
    size_t*           len,
    CK_RV*            rv
);

#endif

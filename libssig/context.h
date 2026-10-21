/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef LIBSSIG_CONTEXT_H
#define LIBSSIG_CONTEXT_H

#include <libssig/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Inicializar con {0}. No copiar ni modificar impl.
 * Mantener abierto durante todas las operaciones y sesiones que lo usan.
 * El consumidor sincroniza el cierre y cualquier reemplazo del contexto. */
typedef struct {
	struct libssig_context_impl* impl;
} libssig_context;

libssig_status libssig_context_open(libssig_context* ctx);
void           libssig_context_close(libssig_context* ctx);

#ifdef __cplusplus
}
#endif

#endif

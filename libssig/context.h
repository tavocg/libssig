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
/* NULL or an empty list preserves p11-kit discovery. A nonempty list loads
 * only those modules, in managed mode. All must load and initialize
 * successfully; failure releases partial state and leaves ctx unopened.
 * Repeated path strings are loaded once. Input strings are borrowed only for
 * the duration of the call. Paths use p11-kit's native filename encoding and
 * resolution rules. */
libssig_status libssig_context_open_modules(
    libssig_context*           ctx,
    const libssig_string_list* paths
);
void libssig_context_close(libssig_context* ctx);

#ifdef __cplusplus
}
#endif

#endif

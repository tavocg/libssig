/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef LIBSSIG_PROVIDER_H
#define LIBSSIG_PROVIDER_H
#include <libssig/context.h>
#include <p11-kit/pkcs11.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Append an already initialized provider without replacing discovered modules.
 * Its function table and initialization must outlive this context. The caller
 * owns initialization/finalization and synchronization across contexts.
 * Repeated function-table pointers are ignored. Failure leaves ctx unchanged.
 */
libssig_status libssig_context_add_provider(
    libssig_context*  ctx,
    CK_FUNCTION_LIST* provider
);
#ifdef __cplusplus
}
#endif
#endif

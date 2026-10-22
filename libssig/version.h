/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef LIBSSIG_VERSION_H
#define LIBSSIG_VERSION_H

#ifdef __cplusplus
extern "C" {
#endif

#define LIBSSIG_VERSION_MAJOR 0
#define LIBSSIG_VERSION_MINOR 1
#define LIBSSIG_VERSION_PATCH 1

/* Escribe la versión de la biblioteca cargada; cada salida puede ser NULL. */
void libssig_version(int* out_major, int* out_minor, int* out_patch);

#ifdef __cplusplus
}
#endif

#endif

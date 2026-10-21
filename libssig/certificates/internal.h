/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef LIBSSIG_CERTIFICATES_INTERNAL_H
#define LIBSSIG_CERTIFICATES_INTERNAL_H

#include <libssig/certificates/certificates.h>
#include <libssig/session.h>

libssig_status libssig_certificates_collect(
    libssig_session*          s,
    libssig_certificate_list* certs,
    unsigned int              options,
    CK_RV*                    out_rv
);

/* Metadatos propiedad del certificado; leer sobre una salida vacía. */
libssig_status libssig_certificate_metadata_read(libssig_certificate* cert);
void           libssig_certificate_metadata_clear(libssig_certificate* cert);

#endif

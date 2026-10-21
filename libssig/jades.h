/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef LIBSSIG_JADES_H
#define LIBSSIG_JADES_H
#include <jansson.h>
#include <libssig/document.h>

typedef struct {
	json_t* root;
	json_t* protected;
	json_t*                 unsigned_items;
	char*                   payload;
	X509*                   cert;
	libssig_signature       signature;
	libssig_validation_data evidence;
} libssig_jades;

void           libssig_jades_free(libssig_jades* doc);
libssig_status libssig_jades_read(
    const libssig_verify_params* params,
    libssig_jades*               doc
);
bool libssig_jades_input(const libssig_jades* doc, libssig_signature* bytes);
bool libssig_jades_archive_input(
    const libssig_jades* doc,
    size_t               count,
    libssig_signature*   bytes
);
bool           libssig_jades_write(json_t* value, libssig_signature* bytes);
libssig_status libssig_jades_alg(
    const char*   name,
    X509*         cert,
    libssig_algo* algo,
    libssig_hash* hash
);
const char*    libssig_jades_alg_name(libssig_algo algo, libssig_hash hash);
json_t*        libssig_jades_item(json_t* value);
bool           libssig_jades_add(libssig_jades* doc, json_t* value);
json_t*        libssig_jades_pki(const libssig_signature* bytes);
bool           libssig_jades_pki_read(json_t* value, libssig_signature* bytes);
libssig_status libssig_jades_evidence_read(libssig_jades* doc, json_t* value);
bool libssig_jades_timestamp_read(json_t* value, libssig_signature* token);
bool libssig_jades_timestamp_add(
    libssig_jades*           doc,
    const char*              kind,
    const libssig_signature* token
);
#endif

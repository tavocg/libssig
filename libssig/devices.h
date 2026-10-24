/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef LIBSSIG_DEVICES_H
#define LIBSSIG_DEVICES_H
#include <libssig/certificates/certificates.h>
#ifdef __cplusplus
extern "C" {
#endif

/* Public metadata only. object_class/key_type/flags retain their PKCS#11
 * numeric values. Missing attributes are NULL/zero; unknown key_type is ~0UL.
 * A matching CKA_ID is an association, never proof of signing capability. */
typedef struct {
	unsigned long  object_class, key_type, bits;
	unsigned char* id;
	size_t         id_len;
	char*          label;
	size_t         label_len;
	bool           size_from_certificate, sign_known, can_sign;
} libssig_device_key;
typedef struct {
	unsigned long            id, flags;
	char *                   description, *manufacturer;
	libssig_token_version    hardware_version, firmware_version;
	bool                     token_present, token_valid;
	libssig_token            token;
	libssig_certificate_list certificates;
	libssig_device_key*      keys;
	size_t                   key_count;
	libssig_status           status;
	unsigned long            ck_rv;
} libssig_device_slot;
typedef struct {
	char *                name, *path, *description, *manufacturer;
	libssig_token_version version, cryptoki_version;
	libssig_device_slot*  slots;
	size_t                slot_count;
	libssig_status        status;
	unsigned long         ck_rv;
} libssig_device_module;
typedef struct {
	libssig_device_module* items;
	size_t                 count;
} libssig_device_list;

enum { LIBSSIG_DEVICES_ALL = 1u << 0 };

/* Snapshot of hardware slots (including empty slots). ALL includes software.
 * Opens read-only public sessions; never logs in, calls a PIN callback, reads
 * secret key material or tests a signature. Certificates include all key
 * usages. Context must remain open for this synchronous call. Results are
 * independent of it afterward. No module handles or object handles escape.
 * Per-module/slot errors preserve other results; inspect their status/ck_rv.
 * Allocation errors clear output; invalid arguments leave it unchanged.
 * Initialize with {0}, free
 * before reuse. Library strings are bytes from the provider, not guaranteed
 * UTF-8. Concurrent context replacement/close must be synchronized by caller.
 */
libssig_status libssig_devices(
    const libssig_context* ctx,
    libssig_device_list*   devices,
    unsigned int           options
);
void libssig_devices_free(libssig_device_list* devices);

/* Slot events and slot metadata are checked on every poll. Token identity is
 * read only on the first poll, after an event or slot change, and at most
 * every LIBSSIG_DEVICES_TOKEN_POLLS polls. Volatile token flags and transient
 * provider errors do not report a change. Does not open sessions. Use one
 * state per context; do not poll one state concurrently. */
#define LIBSSIG_DEVICES_TOKEN_POLLS 5
typedef struct {
	unsigned char slot_fingerprint[32];
	unsigned char token_fingerprint[32];
	unsigned      polls;
	bool          initialized;
} libssig_device_state;
libssig_status libssig_devices_changed(
    const libssig_context* ctx,
    libssig_device_state*  state,
    bool*                  changed,
    unsigned int           options
);
#ifdef __cplusplus
}
#endif
#endif

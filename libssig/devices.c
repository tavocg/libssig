/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <libssig/certificates/internal.h>
#include <libssig/devices.h>
#include <libssig/session.h>
#include <limits.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* CK_ULONG is narrower than size_t on Win64. Keep both conversion and
 * multiplication checks without comparing a promoted 32-bit value directly
 * with a constant derived from 64-bit SIZE_MAX. */
static bool allocation_fits(CK_ULONG count, size_t item_size) {
	size_t size = (size_t)count;
	return (CK_ULONG)size == count && size <= SIZE_MAX / item_size;
}
static char* text_copy(const unsigned char* text, size_t length) {
	while (length && text[length - 1] == ' ') {
		--length;
	}
	char* result = calloc(length + 1, 1);
	if (result) {
		memcpy(result, text, length);
	}
	return result;
}
static void slot_clear(libssig_device_slot* slot) {
	free(slot->description);
	free(slot->manufacturer);
	libssig_token_clear(&slot->token);
	libssig_certificates_free(&slot->certificates);
	for (size_t n = 0; n < slot->key_count; ++n) {
		free(slot->keys[n].id);
		free(slot->keys[n].label);
	}
	free(slot->keys);
}
void libssig_devices_free(libssig_device_list* devices) {
	if (!devices) {
		return;
	}
	for (size_t m = 0; m < devices->count; ++m) {
		libssig_device_module* module = &devices->items[m];
		free(module->name);
		free(module->path);
		free(module->description);
		free(module->manufacturer);
		for (size_t s = 0; s < module->slot_count; ++s) {
			slot_clear(&module->slots[s]);
		}
		free(module->slots);
	}
	free(devices->items);
	*devices = (libssig_device_list){0};
}
static bool scalar(
    libssig_session*  s,
    CK_OBJECT_HANDLE  object,
    CK_ATTRIBUTE_TYPE type,
    void*             out,
    size_t            size
) {
	CK_ATTRIBUTE attr = {type, out, size};
	return s->module->C_GetAttributeValue(s->handle, object, &attr, 1) ==
	           CKR_OK &&
	       attr.ulValueLen == size;
}
/* Optional public metadata may be hidden on private/secret objects. Do not
 * request CKA_VALUE: its contents would be key material for those classes. */
static libssig_status key_bits(
    libssig_session*    session,
    CK_OBJECT_HANDLE    handle,
    libssig_device_key* key,
    CK_RV*              rv
) {
	CK_ULONG          bits = 0;
	CK_ATTRIBUTE_TYPE type = key->key_type == CKK_RSA ? CKA_MODULUS
	                                                  : CKA_EC_PARAMS;
	if (key->key_type == CKK_RSA &&
	    scalar(session, handle, CKA_MODULUS_BITS, &bits, sizeof(bits)) &&
	    bits && bits != CK_UNAVAILABLE_INFORMATION) {
		key->bits = bits;
		return LIBSSIG_OK;
	}
	if (key->object_class == CKO_SECRET_KEY) {
		CK_ULONG bytes = 0;
		if (scalar(session, handle, CKA_VALUE_LEN, &bytes, sizeof(bytes)) &&
		    bytes <= ULONG_MAX / 8) {
			key->bits = bytes * 8;
		}
		return LIBSSIG_OK;
	}
	if (key->key_type != CKK_RSA && key->key_type != CKK_EC) {
		return LIBSSIG_OK;
	}
	unsigned char* data = NULL;
	size_t         size = 0;
	libssig_status status = libssig_attribute_read(
	    session,
	    handle,
	    type,
	    &data,
	    &size,
	    rv
	);
	if (status != LIBSSIG_OK) {
		return status;
	}
	if (data && size && key->key_type == CKK_RSA) {
		size_t n = 0;
		while (n < size && data[n] == 0) {
			++n;
		}
		if (n < size && size - n <= ULONG_MAX / 8) {
			unsigned char top = data[n];
			bits = (size - n - 1) * 8;
			while (top) {
				++bits;
				top >>= 1;
			}
		}
	} else if (data && size <= LONG_MAX) {
		const unsigned char* cursor = data;
		ASN1_OBJECT*         oid = d2i_ASN1_OBJECT(NULL, &cursor, (long)size);
		int nid = oid && cursor == data + size ? OBJ_obj2nid(oid) : NID_undef;
		EC_GROUP* group = nid != NID_undef ? EC_GROUP_new_by_curve_name(nid)
		                                   : NULL;
		if (group) {
			bits = (unsigned long)EC_GROUP_get_degree(group);
		}
		EC_GROUP_free(group);
		ASN1_OBJECT_free(oid);
	}
	free(data);
	ERR_clear_error();
	key->bits = bits;
	return LIBSSIG_OK;
}
static libssig_status read_key(
    libssig_session*     session,
    CK_OBJECT_HANDLE     handle,
    CK_OBJECT_CLASS      kind,
    libssig_device_slot* slot
) {
	if (slot->key_count >= SIZE_MAX / sizeof(*slot->keys)) {
		return LIBSSIG_ERROR_MEMORY;
	}
	libssig_device_key* keys = realloc(
	    slot->keys,
	    (slot->key_count + 1) * sizeof(*keys)
	);
	if (!keys) {
		return LIBSSIG_ERROR_MEMORY;
	}
	slot->keys = keys;
	libssig_device_key* key = &keys[slot->key_count++];
	*key = (libssig_device_key){.object_class = kind,
	                            .key_type = CK_UNAVAILABLE_INFORMATION};
	libssig_status status = libssig_attribute_read(
	    session,
	    handle,
	    CKA_ID,
	    &key->id,
	    &key->id_len,
	    &slot->ck_rv
	);
	if (status != LIBSSIG_OK) {
		return status;
	}
	unsigned char* label = NULL;
	status = libssig_attribute_read(
	    session,
	    handle,
	    CKA_LABEL,
	    &label,
	    &key->label_len,
	    &slot->ck_rv
	);
	key->label = (char*)label;
	if (status != LIBSSIG_OK) {
		return status;
	}
	scalar(
	    session,
	    handle,
	    CKA_KEY_TYPE,
	    &key->key_type,
	    sizeof(key->key_type)
	);
	CK_BBOOL sign = CK_FALSE;
	key->sign_known = scalar(session, handle, CKA_SIGN, &sign, sizeof(sign));
	key->can_sign = key->sign_known && sign == CK_TRUE;
	return key_bits(session, handle, key, &slot->ck_rv);
}
static libssig_status read_keys(
    libssig_session*     session,
    libssig_device_slot* slot
) {
	const CK_OBJECT_CLASS kinds[] =
	    {CKO_PUBLIC_KEY, CKO_PRIVATE_KEY, CKO_SECRET_KEY};
	libssig_status status = LIBSSIG_OK;
	for (size_t k = 0;
	     status == LIBSSIG_OK && k < sizeof(kinds) / sizeof(kinds[0]);
	     ++k) {
		CK_OBJECT_CLASS kind = kinds[k];
		CK_ATTRIBUTE    filter = {CKA_CLASS, &kind, sizeof(kind)};
		slot->ck_rv = session->module
		                  ->C_FindObjectsInit(session->handle, &filter, 1);
		if (slot->ck_rv != CKR_OK) {
			return LIBSSIG_ERROR_PKCS11;
		}
		while (status == LIBSSIG_OK) {
			CK_OBJECT_HANDLE handles[32];
			CK_ULONG         count = 0;
			slot->ck_rv = session->module->C_FindObjects(
			    session->handle,
			    handles,
			    32,
			    &count
			);
			if (slot->ck_rv != CKR_OK) {
				status = LIBSSIG_ERROR_PKCS11;
				break;
			}
			if (count > 32) {
				slot->ck_rv = CKR_GENERAL_ERROR;
				status = LIBSSIG_ERROR_PKCS11;
				break;
			}
			if (!count) {
				break;
			}
			for (CK_ULONG n = 0; status == LIBSSIG_OK && n < count; ++n) {
				status = read_key(session, handles[n], kind, slot);
			}
		}
		CK_RV rv = session->module->C_FindObjectsFinal(session->handle);
		if (status == LIBSSIG_OK && rv != CKR_OK) {
			slot->ck_rv = rv;
			status = LIBSSIG_ERROR_PKCS11;
		}
	}
	for (size_t n = 0; n < slot->key_count; ++n) {
		libssig_device_key* key = &slot->keys[n];
		if (key->bits || !key->id_len || key->object_class == CKO_SECRET_KEY) {
			continue;
		}
		for (size_t c = 0; c < slot->certificates.count; ++c) {
			libssig_certificate* cert = &slot->certificates.items[c];
			if (cert->id_len == key->id_len && cert->id &&
			    !memcmp(key->id, cert->id, key->id_len)) {
				const unsigned char* cursor = cert->der;
				X509*                x509 = cursor && cert->der_len <= LONG_MAX
				                                ? d2i_X509(NULL, &cursor, (long)cert->der_len)
				                                : NULL;
				EVP_PKEY* public_key = x509 ? X509_get_pubkey(x509) : NULL;
				int       type = public_key ? EVP_PKEY_base_id(public_key)
				                            : EVP_PKEY_NONE;
				bool      compatible = (key->key_type == CKK_RSA &&
                                   (type == EVP_PKEY_RSA ||
                                    type == EVP_PKEY_RSA_PSS)) ||
				                  (key->key_type == CKK_EC &&
				                   type == EVP_PKEY_EC) ||
				                  (key->key_type == CKK_DSA &&
				                   type == EVP_PKEY_DSA) ||
				                  key->key_type == CK_UNAVAILABLE_INFORMATION;
				EVP_PKEY_free(public_key);
				X509_free(x509);
				ERR_clear_error();
				if (!compatible) {
					continue;
				}
				key->bits = cert->public_key_bits;
				key->size_from_certificate = key->bits != 0;
				break;
			}
		}
	}
	return status;
}
static libssig_status read_slot(
    CK_FUNCTION_LIST*    module,
    libssig_device_slot* slot,
    unsigned int         options
) {
	CK_SLOT_INFO info = {0};
	slot->ck_rv = module->C_GetSlotInfo(slot->id, &info);
	if (slot->ck_rv != CKR_OK) {
		return LIBSSIG_ERROR_PKCS11;
	}
	slot->description = text_copy(
	    info.slotDescription,
	    sizeof(info.slotDescription)
	);
	slot->manufacturer = text_copy(
	    info.manufacturerID,
	    sizeof(info.manufacturerID)
	);
	if (!slot->description || !slot->manufacturer) {
		return LIBSSIG_ERROR_MEMORY;
	}
	slot->flags = info.flags;
	if (!(options & LIBSSIG_DEVICES_ALL) && !(info.flags & CKF_HW_SLOT)) {
		return LIBSSIG_OK;
	}
	slot->hardware_version = (libssig_token_version){
	    info.hardwareVersion.major,
	    info.hardwareVersion.minor
	};
	slot->firmware_version = (libssig_token_version){
	    info.firmwareVersion.major,
	    info.firmwareVersion.minor
	};
	slot->token_present = (info.flags & CKF_TOKEN_PRESENT) != 0;
	if (!slot->token_present) {
		return LIBSSIG_OK;
	}
	CK_TOKEN_INFO token_info = {0};
	slot->ck_rv = module->C_GetTokenInfo(slot->id, &token_info);
	if (slot->ck_rv != CKR_OK) {
		return LIBSSIG_ERROR_PKCS11;
	}
	libssig_status status = libssig_token_from_info(&token_info, &slot->token);
	if (status != LIBSSIG_OK) {
		return status;
	}
	slot->token_valid = true;
	libssig_session session = {.module = module, .slot = slot->id};
	slot->ck_rv = module->C_OpenSession(
	    slot->id,
	    CKF_SERIAL_SESSION,
	    NULL,
	    NULL,
	    &session.handle
	);
	if (slot->ck_rv != CKR_OK) {
		return LIBSSIG_ERROR_PKCS11;
	}
	status = libssig_certificates_collect(
	    &session,
	    &slot->certificates,
	    LIBSSIG_CERTIFICATES_ALL,
	    &slot->ck_rv
	);
	if (status == LIBSSIG_OK) {
		status = read_keys(&session, slot);
	}
	CK_RV rv = module->C_CloseSession(session.handle);
	if (status == LIBSSIG_OK && rv != CKR_OK) {
		slot->ck_rv = rv;
		status = LIBSSIG_ERROR_PKCS11;
	}
	return status;
}
static libssig_status read_module(
    CK_FUNCTION_LIST*      module,
    libssig_device_module* result,
    unsigned int           options
) {
	CK_INFO info = {0};
	result->ck_rv = module->C_GetInfo(&info);
	if (result->ck_rv != CKR_OK) {
		return LIBSSIG_ERROR_PKCS11;
	}
	result->description = text_copy(
	    info.libraryDescription,
	    sizeof(info.libraryDescription)
	);
	result->manufacturer = text_copy(
	    info.manufacturerID,
	    sizeof(info.manufacturerID)
	);
	result->name = p11_kit_module_get_name(module);
	result->path = p11_kit_module_get_filename(module);
	if (!result->name) {
		result->name = text_copy(
		    info.libraryDescription,
		    sizeof(info.libraryDescription)
		);
	}
	if (!result->description || !result->manufacturer || !result->name) {
		return LIBSSIG_ERROR_MEMORY;
	}
	result->version = (libssig_token_version){info.libraryVersion.major,
	                                          info.libraryVersion.minor};
	result->cryptoki_version = (libssig_token_version){
	    info.cryptokiVersion.major,
	    info.cryptokiVersion.minor
	};
	CK_SLOT_ID* ids = NULL;
	CK_ULONG    count = 0;
	for (unsigned n = 0; n < 3; ++n) {
		result->ck_rv = module->C_GetSlotList(CK_FALSE, NULL, &count);
		if (result->ck_rv != CKR_OK) {
			return LIBSSIG_ERROR_PKCS11;
		}
		if (!allocation_fits(count, sizeof(*ids))) {
			return LIBSSIG_ERROR_MEMORY;
		}
		CK_ULONG capacity = count;
		ids = calloc(count ? (size_t)count : 1, sizeof(*ids));
		if (!ids) {
			return LIBSSIG_ERROR_MEMORY;
		}
		result->ck_rv = module->C_GetSlotList(CK_FALSE, ids, &count);
		if (result->ck_rv != CKR_BUFFER_TOO_SMALL) {
			if (result->ck_rv == CKR_OK && count > capacity) {
				result->ck_rv = CKR_GENERAL_ERROR;
			}
			break;
		}
		free(ids);
		ids = NULL;
	}
	if (result->ck_rv != CKR_OK) {
		free(ids);
		return LIBSSIG_ERROR_PKCS11;
	}
	if (!allocation_fits(count, sizeof(*result->slots))) {
		free(ids);
		return LIBSSIG_ERROR_MEMORY;
	}
	result->slots = calloc(count ? (size_t)count : 1, sizeof(*result->slots));
	if (!result->slots) {
		free(ids);
		return LIBSSIG_ERROR_MEMORY;
	}
	for (size_t n = 0; n < (size_t)count; ++n) {
		libssig_device_slot* slot = &result->slots[result->slot_count];
		slot->id = ids[n];
		slot->status = read_slot(module, slot, options);
		if (slot->status == LIBSSIG_ERROR_MEMORY) {
			++result->slot_count;
			free(ids);
			return LIBSSIG_ERROR_MEMORY;
		}
		if (slot->status == LIBSSIG_OK && !(options & LIBSSIG_DEVICES_ALL) &&
		    !(slot->flags & CKF_HW_SLOT)) {
			slot_clear(slot);
			*slot = (libssig_device_slot){0};
		} else {
			++result->slot_count;
		}
	}
	free(ids);
	return LIBSSIG_OK;
}
libssig_status libssig_devices(
    const libssig_context* ctx,
    libssig_device_list*   devices,
    unsigned int           options
) {
	if (!ctx || !ctx->impl || !devices || devices->items || devices->count ||
	    (options & ~LIBSSIG_DEVICES_ALL)) {
		return LIBSSIG_ERROR_ARGUMENT;
	}
	if (!ctx->impl->modules) {
		return LIBSSIG_OK;
	}
	size_t count = 0;
	while (ctx->impl->modules[count]) {
		++count;
	}
	if (count > SIZE_MAX / sizeof(*devices->items)) {
		return LIBSSIG_ERROR_MEMORY;
	}
	devices->items = calloc(count ? count : 1, sizeof(*devices->items));
	if (!devices->items) {
		return LIBSSIG_ERROR_MEMORY;
	}
	devices->count = count;
	for (size_t n = 0; n < count; ++n) {
		devices->items[n].status = read_module(
		    ctx->impl->modules[n],
		    &devices->items[n],
		    options
		);
		if (devices->items[n].status == LIBSSIG_ERROR_MEMORY) {
			libssig_devices_free(devices);
			return LIBSSIG_ERROR_MEMORY;
		}
	}
	return LIBSSIG_OK;
}

static libssig_status list_slots(
    CK_FUNCTION_LIST* module,
    CK_SLOT_ID**      ids,
    CK_ULONG*         count,
    CK_RV*            rv
) {
	*ids = NULL;
	*count = 0;
	for (unsigned n = 0; n < 3; ++n) {
		CK_ULONG needed = 0;
		*rv = module->C_GetSlotList(CK_FALSE, NULL, &needed);
		if (*rv != CKR_OK) {
			return LIBSSIG_ERROR_PKCS11;
		}
		if (!allocation_fits(needed, sizeof(**ids))) {
			return LIBSSIG_ERROR_MEMORY;
		}
		CK_ULONG    capacity = needed;
		CK_SLOT_ID* list = calloc(needed ? (size_t)needed : 1, sizeof(*list));
		if (!list) {
			return LIBSSIG_ERROR_MEMORY;
		}
		*rv = module->C_GetSlotList(CK_FALSE, list, &needed);
		if (*rv == CKR_BUFFER_TOO_SMALL) {
			free(list);
			continue;
		}
		if (*rv == CKR_OK && needed <= capacity) {
			*ids = list;
			*count = needed;
			return LIBSSIG_OK;
		}
		free(list);
		if (*rv == CKR_OK) {
			*rv = CKR_GENERAL_ERROR;
		}
		return LIBSSIG_ERROR_PKCS11;
	}
	*rv = CKR_BUFFER_TOO_SMALL;
	return LIBSSIG_ERROR_PKCS11;
}
typedef struct {
	size_t     module;
	CK_SLOT_ID id;
} slot_reference;
libssig_status libssig_devices_changed(
    const libssig_context* ctx,
    libssig_device_state*  state,
    bool*                  changed,
    unsigned int           options
) {
	if (!ctx || !ctx->impl || !state || !changed ||
	    (options & ~LIBSSIG_DEVICES_ALL)) {
		return LIBSSIG_ERROR_ARGUMENT;
	}
	*changed = false;
	EVP_MD_CTX* hash = EVP_MD_CTX_new();
	if (!hash) {
		return LIBSSIG_ERROR_MEMORY;
	}
	bool            ok = EVP_DigestInit_ex(hash, EVP_sha256(), NULL) == 1;
	bool            event = false;
	bool            slots_ok = true;
	slot_reference* present = NULL;
	size_t          present_count = 0;
	size_t          present_capacity = 0;
	for (size_t m = 0;
	     ok && slots_ok && ctx->impl->modules && ctx->impl->modules[m];
	     ++m) {
		CK_FUNCTION_LIST* module = ctx->impl->modules[m];
		CK_SLOT_ID        slot_event;
		if (module->C_WaitForSlotEvent &&
		    module->C_WaitForSlotEvent(CKF_DONT_BLOCK, &slot_event, NULL) ==
		        CKR_OK) {
			event = true;
		}
		CK_SLOT_ID*    ids = NULL;
		CK_ULONG       count = 0;
		CK_RV          rv = CKR_OK;
		libssig_status status = list_slots(module, &ids, &count, &rv);
		if (status == LIBSSIG_ERROR_MEMORY) {
			free(present);
			EVP_MD_CTX_free(hash);
			return status;
		}
		if (status != LIBSSIG_OK) {
			slots_ok = false;
			break;
		}
		ok = EVP_DigestUpdate(hash, &m, sizeof(m)) == 1 &&
		     EVP_DigestUpdate(hash, &count, sizeof(count)) == 1;
		for (CK_ULONG s = 0; ok && s < count; ++s) {
			CK_SLOT_INFO info = {0};
			rv = module->C_GetSlotInfo(ids[s], &info);
			if (rv != CKR_OK) {
				slots_ok = false;
				break;
			}
			if (!(options & LIBSSIG_DEVICES_ALL) &&
			    !(info.flags & CKF_HW_SLOT)) {
				continue;
			}
			ok = EVP_DigestUpdate(hash, &ids[s], sizeof(ids[s])) == 1 &&
			     EVP_DigestUpdate(
			         hash,
			         info.slotDescription,
			         sizeof(info.slotDescription)
			     ) == 1 &&
			     EVP_DigestUpdate(hash, &info.flags, sizeof(info.flags)) == 1;
			if (!(info.flags & CKF_TOKEN_PRESENT)) {
				continue;
			}
			if (present_count == present_capacity) {
				size_t capacity = present_capacity ? present_capacity * 2 : 8;
				if (capacity < present_capacity ||
				    capacity > SIZE_MAX / sizeof(*present)) {
					ok = false;
					break;
				}
				slot_reference* grown = realloc(
				    present,
				    capacity * sizeof(*present)
				);
				if (!grown) {
					free(present);
					free(ids);
					EVP_MD_CTX_free(hash);
					return LIBSSIG_ERROR_MEMORY;
				}
				present = grown;
				present_capacity = capacity;
			}
			present[present_count++] = (slot_reference){m, ids[s]};
		}
		free(ids);
	}
	unsigned char slot_fingerprint[32];
	unsigned int  length = 0;
	if (!slots_ok) {
		free(present);
		EVP_MD_CTX_free(hash);
		*changed = event;
		return LIBSSIG_OK;
	}
	ok = ok && EVP_DigestFinal_ex(hash, slot_fingerprint, &length) == 1 &&
	     length == sizeof(slot_fingerprint);
	EVP_MD_CTX_free(hash);
	if (!ok) {
		free(present);
		return LIBSSIG_ERROR_CRYPTO;
	}
	bool slot_changed = !state->initialized || memcmp(
	                                               state->slot_fingerprint,
	                                               slot_fingerprint,
	                                               sizeof(slot_fingerprint)
	                                           ) != 0;
	bool refresh = !state->initialized || event || slot_changed ||
	               state->polls >= LIBSSIG_DEVICES_TOKEN_POLLS;
	bool          token_ok = false;
	unsigned char token_fingerprint[32] = {0};
	if (refresh) {
		EVP_MD_CTX* token_hash = EVP_MD_CTX_new();
		if (!token_hash) {
			free(present);
			return LIBSSIG_ERROR_MEMORY;
		}
		token_ok = EVP_DigestInit_ex(token_hash, EVP_sha256(), NULL) == 1;
		for (size_t n = 0; token_ok && n < present_count; ++n) {
			CK_TOKEN_INFO token = {0};
			CK_RV rv = ctx->impl->modules[present[n].module]->C_GetTokenInfo(
			    present[n].id,
			    &token
			);
			if (rv != CKR_OK) {
				token_ok = false;
				break;
			}
			/* Exclude session counters, free memory, clocks and volatile PIN
			 * flags: using the token must not look like replacement. */
			token_ok = EVP_DigestUpdate(
			               token_hash,
			               &present[n].module,
			               sizeof(present[n].module)
			           ) == 1 &&
			           EVP_DigestUpdate(
			               token_hash,
			               &present[n].id,
			               sizeof(present[n].id)
			           ) == 1 &&
			           EVP_DigestUpdate(
			               token_hash,
			               token.label,
			               sizeof(token.label)
			           ) == 1 &&
			           EVP_DigestUpdate(
			               token_hash,
			               token.manufacturerID,
			               sizeof(token.manufacturerID)
			           ) == 1 &&
			           EVP_DigestUpdate(
			               token_hash,
			               token.model,
			               sizeof(token.model)
			           ) == 1 &&
			           EVP_DigestUpdate(
			               token_hash,
			               token.serialNumber,
			               sizeof(token.serialNumber)
			           ) == 1;
		}
		length = 0;
		token_ok = token_ok &&
		           EVP_DigestFinal_ex(token_hash, token_fingerprint, &length) ==
		               1 &&
		           length == sizeof(token_fingerprint);
		EVP_MD_CTX_free(token_hash);
	}
	free(present);
	bool token_changed = token_ok && memcmp(
	                                     state->token_fingerprint,
	                                     token_fingerprint,
	                                     sizeof(token_fingerprint)
	                                 ) != 0;
	*changed = event || slot_changed || token_changed;
	memcpy(state->slot_fingerprint, slot_fingerprint, sizeof(slot_fingerprint));
	if (token_ok) {
		memcpy(
		    state->token_fingerprint,
		    token_fingerprint,
		    sizeof(token_fingerprint)
		);
		state->polls = 0;
	} else if (refresh) {
		/* Keep the previous identity and retry on the next poll. */
		state->polls = LIBSSIG_DEVICES_TOKEN_POLLS;
	} else if (state->polls < UINT_MAX) {
		++state->polls;
	}
	state->initialized = true;
	return LIBSSIG_OK;
}

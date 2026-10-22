/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "internal.h"
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct {
	CK_MECHANISM           mechanism;
	CK_RSA_PKCS_PSS_PARAMS pss;
	CK_KEY_TYPE            key_type;
} sign_plan;

static libssig_status sign_plan_create(
    const libssig_key_sign_params* params,
    sign_plan*                     plan
) {
	static const struct {
		libssig_hash         hash;
		CK_MECHANISM_TYPE    digest;
		CK_RSA_PKCS_MGF_TYPE mgf;
		CK_ULONG             len;
		CK_MECHANISM_TYPE    mechanisms[3];
	} hashes[] = {
	    {
	        LIBSSIG_HASH_SHA256,
	        CKM_SHA256,
	        CKG_MGF1_SHA256,
	        32,
	        {
	            CKM_SHA256_RSA_PKCS,
	            CKM_SHA256_RSA_PKCS_PSS,
	            CKM_ECDSA_SHA256,
	        },
	    },
	    {
	        LIBSSIG_HASH_SHA384,
	        CKM_SHA384,
	        CKG_MGF1_SHA384,
	        48,
	        {
	            CKM_SHA384_RSA_PKCS,
	            CKM_SHA384_RSA_PKCS_PSS,
	            CKM_ECDSA_SHA384,
	        },
	    },
	    {
	        LIBSSIG_HASH_SHA512,
	        CKM_SHA512,
	        CKG_MGF1_SHA512,
	        64,
	        {
	            CKM_SHA512_RSA_PKCS,
	            CKM_SHA512_RSA_PKCS_PSS,
	            CKM_ECDSA_SHA512,
	        },
	    },
	};

	if (params->algo < LIBSSIG_ALGO_RSA_PKCS ||
	    params->algo > LIBSSIG_ALGO_ECDSA) {
		return LIBSSIG_ERROR_UNSUPPORTED;
	}

	for (size_t i = 0; i < sizeof(hashes) / sizeof(hashes[0]); ++i) {
		if (params->hash != hashes[i].hash) {
			continue;
		}

		plan->key_type = params->algo == LIBSSIG_ALGO_ECDSA ? CKK_EC : CKK_RSA;
		plan->mechanism.mechanism = hashes[i].mechanisms[params->algo];
		if (params->algo == LIBSSIG_ALGO_RSA_PSS) {
			plan->pss = (CK_RSA_PKCS_PSS_PARAMS){
			    hashes[i].digest,
			    hashes[i].mgf,
			    hashes[i].len,
			};

			plan->mechanism.pParameter = &plan->pss;
			plan->mechanism.ulParameterLen = sizeof(plan->pss);
		}

		return LIBSSIG_OK;
	}

	return LIBSSIG_ERROR_UNSUPPORTED;
}

static libssig_status key_authentication_get(
    libssig_session* s,
    CK_OBJECT_HANDLE key,
    CK_BBOOL*        out_required,
    CK_RV*           out_rv
) {
	CK_ATTRIBUTE attribute = {
	    CKA_ALWAYS_AUTHENTICATE,
	    out_required,
	    sizeof(*out_required),
	};

	*out_required = CK_FALSE;
	*out_rv = s->module->C_GetAttributeValue(s->handle, key, &attribute, 1);
	if (*out_rv == CKR_ATTRIBUTE_TYPE_INVALID) {
		*out_required = CK_FALSE;
		*out_rv = CKR_OK;
		return LIBSSIG_OK;
	}

	if (*out_rv != CKR_OK) {
		return LIBSSIG_ERROR_PKCS11;
	}

	if (attribute.ulValueLen != sizeof(*out_required)) {
		return LIBSSIG_ERROR_UNSUPPORTED;
	}

	return LIBSSIG_OK;
}

static libssig_status sign_operation_init(
    libssig_session*               s,
    CK_OBJECT_HANDLE               key,
    const libssig_key_sign_params* params,
    sign_plan*                     plan,
    CK_RV*                         out_rv
) {
	CK_BBOOL       required = CK_FALSE;
	libssig_status status = key_authentication_get(s, key, &required, out_rv);
	if (status != LIBSSIG_OK) {
		return status;
	}

	*out_rv = s->module->C_SignInit(s->handle, &plan->mechanism, key);
	if (*out_rv != CKR_OK) {
		return LIBSSIG_ERROR_PKCS11;
	}

	if (required == CK_TRUE) {
		*out_rv = s->module->C_Login(
		    s->handle,
		    CKU_CONTEXT_SPECIFIC,
		    (CK_UTF8CHAR_PTR)params->pin,
		    (CK_ULONG)params->pin_len
		);
	}

	return *out_rv == CKR_OK ? LIBSSIG_OK : LIBSSIG_ERROR_PKCS11;
}

static libssig_status signature_allocate(
    libssig_session*   s,
    CK_BYTE_PTR        data,
    CK_ULONG           data_len,
    libssig_signature* signature,
    CK_ULONG*          out_capacity
) {
	*out_capacity = 0;
	signature->ck_rv = s->module->C_Sign(
	    s->handle,
	    data,
	    data_len,
	    NULL,
	    out_capacity
	);
	if (signature->ck_rv != CKR_OK) {
		return LIBSSIG_ERROR_PKCS11;
	}

	size_t capacity = (size_t)*out_capacity;
	if (!capacity || (CK_ULONG)capacity != *out_capacity) {
		return LIBSSIG_ERROR_MEMORY;
	}

	signature->data = malloc(capacity);
	return signature->data ? LIBSSIG_OK : LIBSSIG_ERROR_MEMORY;
}

static libssig_status signature_read(
    libssig_session*               s,
    const libssig_key_sign_params* params,
    libssig_signature*             signature
) {
	unsigned char  empty = 0;
	CK_BYTE_PTR    data = params->data ? (CK_BYTE_PTR)params->data : &empty;
	CK_ULONG       capacity = 0;
	libssig_status status = signature_allocate(
	    s,
	    data,
	    (CK_ULONG)params->data_len,
	    signature,
	    &capacity
	);

	if (status != LIBSSIG_OK) {
		return status;
	}

	CK_ULONG len = capacity;
	signature->ck_rv = s->module->C_Sign(
	    s->handle,
	    data,
	    (CK_ULONG)params->data_len,
	    signature->data,
	    &len
	);

	if (signature->ck_rv != CKR_OK) {
		return LIBSSIG_ERROR_PKCS11;
	}

	if (!len || len > capacity) {
		signature->ck_rv = CKR_GENERAL_ERROR;
		return LIBSSIG_ERROR_PKCS11;
	}

	signature->len = (size_t)len;
	return LIBSSIG_OK;
}

static libssig_status session_sign(
    libssig_session*               s,
    const libssig_key_sign_params* params,
    sign_plan*                     plan,
    libssig_signature*             signature
) {
	CK_RV rv = CKR_OK;
	libssig_status
	    status = libssig_session_login(s, params->pin, params->pin_len, &rv);
	CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
	if (status == LIBSSIG_OK) {
		status = libssig_private_key_find(
		    s,
		    params->id,
		    params->id_len,
		    plan->key_type,
		    &key,
		    &rv
		);
	}

	if (status == LIBSSIG_OK) {
		status = sign_operation_init(s, key, params, plan, &rv);
	}

	signature->ck_rv = rv;

	return status == LIBSSIG_OK ? signature_read(s, params, signature) : status;
}

static bool sign_params_valid(const libssig_key_sign_params* params) {
	return params && params->token && params->token->uri && params->id &&
	       params->id_len && params->id_len <= ULONG_MAX &&
	       (params->pin || !params->pin_len) && params->pin_len <= ULONG_MAX &&
	       (params->data || !params->data_len) && params->data_len <= ULONG_MAX;
}

static libssig_status signature_finish(
    libssig_session*   s,
    libssig_status     status,
    libssig_signature* signature
) {
	CK_RV rv = signature->ck_rv;
	CK_RV close_rv = libssig_session_close(s);
	if (status == LIBSSIG_OK && close_rv != CKR_OK) {
		rv = close_rv;
		status = LIBSSIG_ERROR_PKCS11;
	}

	if (status != LIBSSIG_OK) {
		libssig_signature_free(signature);
	}

	signature->ck_rv = rv;

	return status;
}

libssig_status libssig_session_sign(
    const libssig_context*         ctx,
    const libssig_key_sign_params* params,
    libssig_signature*             signature
) {
	if (!signature) {
		return LIBSSIG_ERROR_ARGUMENT;
	}

	*signature = (libssig_signature){0};
	if (!sign_params_valid(params)) {
		return LIBSSIG_ERROR_ARGUMENT;
	}

	sign_plan      plan = {0};
	libssig_status status = sign_plan_create(params, &plan);
	if (status != LIBSSIG_OK) {
		return status;
	}

	libssig_session s = {0};
	CK_RV           rv = CKR_OK;
	status = libssig_session_open(ctx, params->token->uri, &s, &rv);
	signature->ck_rv = rv;
	if (status != LIBSSIG_OK) {
		return status;
	}

	status = session_sign(&s, params, &plan, signature);

	return signature_finish(&s, status, signature);
}

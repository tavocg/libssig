/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "internal.h"
#include <libssig/ades.h>
#include <libssig/document.h>
#include <libssig/multisign.h>
#include <libssig/xades.h>
#include <limits.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool mime_type_valid(const char* type) {
	if (!type) {
		return true;
	}

	size_t      len = strlen(type);
	const char* slash = strchr(type, '/');
	if (!len || len > 255 || !slash || slash == type ||
	    slash == type + len - 1) {
		return false;
	}

	for (size_t i = 0; i < len; ++i) {
		if ((unsigned char)type[i] < 0x20 || (unsigned char)type[i] > 0x7e) {
			return false;
		}
	}
	return true;
}

static libssig_status params_check(
    const libssig_context*     ctx,
    const libssig_sign_params* params
) {
	if (!ctx || !ctx->impl || !ctx->impl->modules || !params ||
	    !params->token || !params->token->uri || !params->cert ||
	    !params->cert->id || !params->cert->id_len ||
	    params->cert->id_len > ULONG_MAX || !params->cert->der ||
	    !params->cert->der_len || params->cert->der_len > LONG_MAX ||
	    (params->data_len && !params->data) || params->data_len > INT_MAX ||
	    (params->pin_len && !params->pin) || params->pin_len > ULONG_MAX ||
	    (params->content_len && !params->content) ||
	    params->content_len > INT_MAX) {
		return LIBSSIG_ERROR_ARGUMENT;
	}

	if ((params->format != LIBSSIG_FORMAT_CADES &&
	     params->format != LIBSSIG_FORMAT_CMS &&
	     params->format != LIBSSIG_FORMAT_PADES &&
	     params->format != LIBSSIG_FORMAT_XADES &&
	     params->format != LIBSSIG_FORMAT_JADES) ||
	    (params->algo != LIBSSIG_ALGO_RSA_PKCS &&
	     params->algo != LIBSSIG_ALGO_RSA_PSS &&
	     params->algo != LIBSSIG_ALGO_ECDSA) ||
	    (params->hash != LIBSSIG_HASH_SHA256 &&
	     params->hash != LIBSSIG_HASH_SHA384 &&
	     params->hash != LIBSSIG_HASH_SHA512)) {
		return LIBSSIG_ERROR_UNSUPPORTED;
	}

	if (!libssig_level_valid(params->level)) {
		return LIBSSIG_ERROR_ARGUMENT;
	}
	if (params->format == LIBSSIG_FORMAT_CMS &&
	    params->level != LIBSSIG_LEVEL_B_B) {
		return LIBSSIG_ERROR_UNSUPPORTED;
	}
	if (params->level != LIBSSIG_LEVEL_B_B &&
	    (!params->services || !params->services->exchange ||
	     !params->services->tsa_url)) {
		return LIBSSIG_ERROR_ARGUMENT;
	}

	if (params->options & ~LIBSSIG_SIGN_DETACHED) {
		return LIBSSIG_ERROR_ARGUMENT;
	}

	if ((params->format == LIBSSIG_FORMAT_CADES ||
	     params->format == LIBSSIG_FORMAT_JADES ||
	     params->format == LIBSSIG_FORMAT_XADES) &&
	    !mime_type_valid(params->mime_type)) {
		return LIBSSIG_ERROR_ARGUMENT;
	}
	return LIBSSIG_OK;
}

static libssig_status sign_new(
    const libssig_context*     ctx,
    const libssig_sign_params* params,
    libssig_signature*         signature
) {
	if (!signature) {
		return LIBSSIG_ERROR_ARGUMENT;
	}

	*signature = (libssig_signature){0};
	libssig_status status = params_check(ctx, params);
	if (status != LIBSSIG_OK) {
		return status;
	}

	if (params->format == LIBSSIG_FORMAT_JADES) {
		return libssig_jades_v121_sign(ctx, params, signature);
	}
	if (params->format == LIBSSIG_FORMAT_XADES) {
		return libssig_xades_v131_sign(ctx, params, signature);
	}
	if (params->format == LIBSSIG_FORMAT_PADES) {
		return libssig_pades_v121_sign(ctx, params, NULL, signature);
	}

	libssig_key_sign_params signing = {
	    .token = params->token,
	    .id = params->cert->id,
	    .id_len = params->cert->id_len,
	    .pin = params->pin,
	    .pin_len = params->pin_len,
	    .data = params->data,
	    .data_len = params->data_len,
	    .algo = params->algo,
	    .hash = params->hash,
	    .mime_type = params->mime_type,
	    .options = params->options,
	};
	status = params->format == LIBSSIG_FORMAT_CADES
	             ? libssig_cades_v131_sign(
	                   ctx,
	                   &signing,
	                   params->cert,
	                   signature
	               )
	             : libssig_cms_sign(ctx, &signing, params->cert, signature);
	if (status == LIBSSIG_OK && params->level != LIBSSIG_LEVEL_B_B) {
		static const unsigned char empty = 0;
		libssig_extend_params      extend = {
		         .data = signature->data,
		         .data_len = signature->len,
		         .content = params->options & LIBSSIG_SIGN_DETACHED
		                        ? (params->data ? params->data : &empty)
		                        : NULL,
		         .content_len = params->options & LIBSSIG_SIGN_DETACHED
		                            ? params->data_len
		                            : 0,
		         .level = params->level,
		         .hash = params->hash,
		         .services = params->services,
        };
		libssig_signature output = {0};
		status = libssig_extend(&extend, &output);
		libssig_signature_free(signature);
		if (status == LIBSSIG_OK) {
			*signature = output;
		}
	}
	return status;
}

bool libssig_signed_format(
    const unsigned char* data,
    size_t               length,
    libssig_format*      format
) {
	libssig_multisign doc = {0};
	libssig_status    status = libssig_multisign_read(data, length, &doc);
	if (status == LIBSSIG_OK && format) {
		*format = doc.format;
	}
	libssig_multisign_free(&doc);
	return status == LIBSSIG_OK;
}
libssig_status libssig_sign(
    const libssig_context*     ctx,
    const libssig_sign_params* params,
    libssig_signature*         output
) {
	if (!output) {
		return LIBSSIG_ERROR_ARGUMENT;
	}
	*output = (libssig_signature){0};
	libssig_status status = params_check(ctx, params);
	if (status != LIBSSIG_OK) {
		return status;
	}
	libssig_multisign doc = {0};
	status = libssig_multisign_read(params->data, params->data_len, &doc);
	bool cms = (params->format == LIBSSIG_FORMAT_CADES ||
	            params->format == LIBSSIG_FORMAT_CMS) &&
	           (doc.format == LIBSSIG_FORMAT_CADES ||
	            doc.format == LIBSSIG_FORMAT_CMS);
	if (status == LIBSSIG_ERROR_NOT_FOUND ||
	    (status == LIBSSIG_OK && !cms && doc.format != params->format)) {
		libssig_multisign_free(&doc);
		return sign_new(ctx, params, output);
	}
	libssig_signature content = {0}, added = {0};
	bool              detached = false;
	if (status == LIBSSIG_OK) {
		status = libssig_multisign_content(
		    &doc,
		    params->content,
		    params->content_len,
		    &content,
		    &detached
		);
	}
	/* Never append a signature over a different detached payload, or bless a
	 * container whose existing cryptographic signatures are already broken. */
	for (size_t i = 0; status == LIBSSIG_OK && i < doc.count; ++i) {
		libssig_verify_params verify = {
		    .data = doc.parts[i].data,
		    .data_len = doc.parts[i].len,
		    .content = params->content,
		    .content_len = params->content_len,
		    .options = LIBSSIG_VERIFY_CURRENT_TIME
		};
		libssig_verify_result result = {0};
		libssig_status        checked = libssig_verify(&verify, &result);
		if (!result.signature_valid ||
		    (checked != LIBSSIG_OK && checked != LIBSSIG_ERROR_TRUST)) {
			status = checked == LIBSSIG_OK ? LIBSSIG_ERROR_VERIFY : checked;
		}
		libssig_verify_free(&result);
	}
	libssig_sign_params next = *params;
	next.data = content.data;
	next.data_len = content.len;
	next.content = NULL;
	next.content_len = 0;
	next.options = detached ? LIBSSIG_SIGN_DETACHED : 0;
	if (status == LIBSSIG_OK && doc.format == LIBSSIG_FORMAT_XADES) {
		unsigned char random[16];
		char          id[48] = "Signature-";
		if (RAND_bytes(random, sizeof(random)) != 1) {
			status = LIBSSIG_ERROR_CRYPTO;
		}
		for (size_t i = 0; status == LIBSSIG_OK && i < sizeof(random); ++i) {
			snprintf(id + 10 + i * 2, 3, "%02x", random[i]);
		}
		if (status == LIBSSIG_OK) {
			status = libssig_xades_v131_sign_named(ctx, &next, id, &added);
		}
	} else if (status == LIBSSIG_OK) {
		status = sign_new(ctx, &next, &added);
	}
	if (status == LIBSSIG_OK && doc.count >= 1024) {
		status = LIBSSIG_ERROR_UNSUPPORTED;
	}
	if (status == LIBSSIG_OK) {
		libssig_signature* parts = realloc(
		    doc.parts,
		    (doc.count + 1) * sizeof(*parts)
		);
		if (!parts) {
			status = LIBSSIG_ERROR_MEMORY;
		} else {
			doc.parts = parts;
			doc.parts[doc.count++] = added;
			added = (libssig_signature){0};
		}
	}
	if (status == LIBSSIG_OK) {
		status = libssig_multisign_merge(&doc, output);
	}
	if (status != LIBSSIG_OK) {
		libssig_signature_free(output);
		output->ck_rv = added.ck_rv;
	}
	libssig_signature_free(&added);
	libssig_signature_free(&content);
	libssig_multisign_free(&doc);
	return status;
}

libssig_status libssig_sign_pdf(
    const libssig_context*        ctx,
    const libssig_sign_params*    params,
    const libssig_pdf_appearance* appearance,
    libssig_signature*            signature
) {
	if (!signature) {
		return LIBSSIG_ERROR_ARGUMENT;
	}
	*signature = (libssig_signature){0};
	libssig_status status = params_check(ctx, params);
	if (status != LIBSSIG_OK) {
		return status;
	}
	if (params->format != LIBSSIG_FORMAT_PADES) {
		return LIBSSIG_ERROR_ARGUMENT;
	}
	return libssig_pades_v121_sign(ctx, params, appearance, signature);
}

libssig_status libssig_document_sign(
    const libssig_context*     ctx,
    const libssig_sign_params* params,
    const libssig_signature*   input,
    libssig_signature*         output
) {
	libssig_key_sign_params signing = {
	    .token = params->token,
	    .id = params->cert->id,
	    .id_len = params->cert->id_len,
	    .pin = params->pin,
	    .pin_len = params->pin_len,
	    .data = input->data,
	    .data_len = input->len,
	    .algo = params->algo,
	    .hash = params->hash
	};
	libssig_status       status = libssig_session_sign(ctx, &signing, output);
	const unsigned char* cursor = params->cert->der;
	X509* cert = d2i_X509(NULL, &cursor, (long)params->cert->der_len);
	if (status == LIBSSIG_OK &&
	    (!cert || cursor != params->cert->der + params->cert->der_len ||
	     !libssig_document_signature_check(
	         cert,
	         params->algo,
	         params->hash,
	         input->data,
	         input->len,
	         output
	     ))) {
		status = LIBSSIG_ERROR_VERIFY;
	}
	X509_free(cert);
	if (status != LIBSSIG_OK) {
		unsigned long rv = output->ck_rv;
		libssig_signature_free(output);
		output->ck_rv = rv;
	}
	return status;
}

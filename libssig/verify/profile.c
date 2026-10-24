/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "internal.h"
#include <string.h>

static const ASN1_TYPE* signed_attribute(CMS_SignerInfo* s, int nid) {
	int pos = CMS_signed_get_attr_by_NID(s, nid, -1);
	if (pos < 0 || CMS_signed_get_attr_by_NID(s, nid, pos) >= 0) {
		return NULL;
	}
	X509_ATTRIBUTE* attr = CMS_signed_get_attr(s, pos);
	return X509_ATTRIBUTE_count(attr) == 1 ? X509_ATTRIBUTE_get0_type(attr, 0)
	                                       : NULL;
}

static bool baseline_present(CMS_SignerInfo* s, bool pades) {
	const ASN1_TYPE* type = signed_attribute(s, NID_pkcs9_contentType);
	const ASN1_TYPE* digest = signed_attribute(s, NID_pkcs9_messageDigest);
	const ASN1_TYPE* cert = signed_attribute(
	    s,
	    NID_id_smime_aa_signingCertificateV2
	);
	if (!cert) {
		cert = signed_attribute(s, NID_id_smime_aa_signingCertificate);
	}
	const ASN1_TYPE* generated = signed_attribute(s, NID_pkcs9_signingTime);
	bool             time_valid = generated &&
	                  (generated->type == V_ASN1_UTCTIME ||
	                   generated->type == V_ASN1_GENERALIZEDTIME) &&
	                  ASN1_TIME_check((ASN1_TIME*)generated->value.asn1_string);
	return type && type->type == V_ASN1_OBJECT && digest &&
	       digest->type == V_ASN1_OCTET_STRING && cert &&
	       cert->type == V_ASN1_SEQUENCE && (pades || time_valid);
}

static bool archive_present(CMS_SignerInfo* s) {
	for (int i = 0; i < CMS_unsigned_get_attr_count(s); ++i) {
		X509_ATTRIBUTE* attr = CMS_unsigned_get_attr(s, i);
		char            oid[80];
		int             len = OBJ_obj2txt(
            oid,
            sizeof(oid),
            X509_ATTRIBUTE_get0_object(attr),
            1
        );
		if (len > 0 && len < (int)sizeof(oid) &&
		    (!strcmp(oid, LIBSSIG_ARCHIVE_OID) ||
		     !strcmp(oid, "1.2.840.113549.1.9.16.2.27") ||
		     !strcmp(oid, "1.2.840.113549.1.9.16.2.48"))) {
			return true;
		}
	}
	return false;
}

void libssig_verify_profiles_detect(
    CMS_ContentInfo*       cms,
    bool                   pades,
    bool                   revocations,
    libssig_verify_result* result
) {
	result->format = pades ? LIBSSIG_FORMAT_PADES : LIBSSIG_FORMAT_CMS;
	STACK_OF(CMS_SignerInfo)* signers = CMS_get0_SignerInfos(cms);
	for (size_t i = 0; i < result->count; ++i) {
		CMS_SignerInfo*        s = sk_CMS_SignerInfo_value(signers, (int)i);
		libssig_verify_signer* signer = &result->signers[i];
		const ASN1_TYPE* generated = signed_attribute(s, NID_pkcs9_signingTime);
		time_t           at;
		if (generated &&
		    (generated->type == V_ASN1_UTCTIME ||
		     generated->type == V_ASN1_GENERALIZEDTIME) &&
		    libssig_time_read((ASN1_TIME*)generated->value.asn1_string, &at)) {
			libssig_time_format(at, signer->signing_time);
		}
		signer->level_detected = baseline_present(s, pades);
		signer->level = LIBSSIG_LEVEL_B_B;
		if (signer->level_detected && !pades) {
			result->format = LIBSSIG_FORMAT_CADES;
		}

		if (CMS_unsigned_get_attr_by_NID(
		        s,
		        NID_id_smime_aa_timeStampToken,
		        -1
		    ) >= 0) {
			signer->level = revocations ? LIBSSIG_LEVEL_B_LT
			                            : LIBSSIG_LEVEL_B_T;
		}

		if (archive_present(s)) {
			signer->level = LIBSSIG_LEVEL_B_LTA;
		}
	}
}

void libssig_verify_profiles_upgrade(
    bool                   revocations,
    libssig_verify_result* result
) {
	for (size_t i = 0; i < result->count; ++i) {
		libssig_verify_signer* s = &result->signers[i];
		if (s->archive.present) {
			s->level = LIBSSIG_LEVEL_B_LTA;
		} else if (s->timestamp.present) {
			s->level = revocations ? LIBSSIG_LEVEL_B_LT : LIBSSIG_LEVEL_B_T;
		}
	}
}

void libssig_verify_profiles_finish(
    libssig_status         status,
    libssig_verify_result* result
) {
	for (size_t i = 0; i < result->count; ++i) {
		libssig_verify_signer* s = &result->signers[i];
		s->level_validated = status == LIBSSIG_OK && s->level_detected &&
		                     result->trust_checked && result->trusted &&
		                     !s->trust_error;
		if (s->level != LIBSSIG_LEVEL_B_B) {
			s->level_validated = s->level_validated && s->timestamp.valid &&
			                     s->timestamp.trusted;
		}

		if (s->level == LIBSSIG_LEVEL_B_LT || s->level == LIBSSIG_LEVEL_B_LTA) {
			s->level_validated = s->level_validated && s->revocation_checked;
		}

		if (s->level == LIBSSIG_LEVEL_B_LTA) {
			s->level_validated = s->level_validated &&
			                     s->history == LIBSSIG_HISTORY_VALID;
		}
	}
}

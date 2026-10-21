/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "internal.h"
#include <stdint.h>
#include <stdio.h>
#include <time.h>

static bool time_copy(const ASN1_TIME* value, char output[21]) {
	if (!value) {
		return true;
	}
	struct tm t;
	return ASN1_TIME_to_tm(value, &t) && snprintf(
	                                         output,
	                                         21,
	                                         "%04d-%02d-%02dT%02d:%02d:%02dZ",
	                                         t.tm_year + 1900,
	                                         t.tm_mon + 1,
	                                         t.tm_mday,
	                                         t.tm_hour,
	                                         t.tm_min,
	                                         t.tm_sec
	                                     ) == 20;
}

static bool age_valid(
    const ASN1_TIME* value,
    const ASN1_TIME* now,
    unsigned long    max_age,
    unsigned long    skew
) {
	int days, seconds;
	if (!value || !ASN1_TIME_diff(&days, &seconds, value, now)) {
		return false;
	}
	int64_t age = (int64_t)days * 86400 + seconds;
	return age >= -(int64_t)skew &&
	       (age <= (int64_t)max_age || age - (int64_t)max_age <= (int64_t)skew);
}

static bool ordering_valid(
    const ASN1_TIME* earlier,
    const ASN1_TIME* later,
    unsigned long    skew
) {
	int days, seconds;
	if (!earlier || !later ||
	    !ASN1_TIME_diff(&days, &seconds, earlier, later)) {
		return false;
	}
	return (int64_t)days * 86400 + seconds >= -(int64_t)skew;
}

static bool freshness_valid(
    const libssig_ocsp_verify_params* params,
    const ASN1_TIME*                  produced,
    ASN1_TIME*                        current,
    ASN1_TIME*                        next,
    ASN1_TIME*                        revoked
) {
	unsigned long max_age = params->max_age ? params->max_age : 86400;
	unsigned long skew = params->clock_skew ? params->clock_skew : 300;
	time_t        clock = time(NULL);
	ASN1_TIME*    now = clock != (time_t)-1 ? ASN1_TIME_set(NULL, clock) : NULL;
	bool          ok = now && age_valid(current, now, max_age, skew) &&
	          age_valid(produced, now, max_age, skew) &&
	          ordering_valid(current, produced, skew) &&
	          (!next || (ordering_valid(now, next, skew) &&
	                     ordering_valid(current, next, 0))) &&
	          (!revoked || ordering_valid(revoked, produced, skew));
	ASN1_TIME_free(now);
	return ok;
}

libssig_status libssig_ocsp_status_read(
    const libssig_ocsp_verify_params* params,
    OCSP_BASICRESP*                   basic,
    OCSP_CERTID*                      id,
    libssig_ocsp_result*              result
) {
	int i = OCSP_resp_find(basic, id, -1);
	if (i < 0) {
		return LIBSSIG_ERROR_NOT_FOUND;
	}

	if (OCSP_resp_find(basic, id, i) >= 0) {
		return LIBSSIG_ERROR_AMBIGUOUS;
	}
	OCSP_SINGLERESP* item = OCSP_resp_get0(basic, i);
	for (int j = 0; j < OCSP_SINGLERESP_get_ext_count(item); ++j) {
		if (X509_EXTENSION_get_critical(OCSP_SINGLERESP_get_ext(item, j))) {
			return LIBSSIG_ERROR_UNSUPPORTED;
		}
	}

	ASN1_GENERALIZEDTIME *revoked = NULL, *current = NULL, *next = NULL;
	int                   reason = -1;
	int                   status = OCSP_single_get0_status(
        item,
        &reason,
        &revoked,
        &current,
        &next
    );
	const ASN1_GENERALIZEDTIME* produced = OCSP_resp_get0_produced_at(basic);
	if ((status != V_OCSP_CERTSTATUS_GOOD &&
	     status != V_OCSP_CERTSTATUS_REVOKED &&
	     status != V_OCSP_CERTSTATUS_UNKNOWN) ||
	    (status == V_OCSP_CERTSTATUS_REVOKED && !revoked) ||
	    !freshness_valid(params, produced, current, next, revoked)) {
		return LIBSSIG_ERROR_VERIFY;
	}

	if (!time_copy(produced, result->produced_at) ||
	    !time_copy(current, result->this_update) ||
	    !time_copy(next, result->next_update) ||
	    !time_copy(revoked, result->revocation_time)) {
		return LIBSSIG_ERROR_VERIFY;
	}
	result->status = status == V_OCSP_CERTSTATUS_GOOD ? LIBSSIG_OCSP_GOOD
	                 : status == V_OCSP_CERTSTATUS_REVOKED
	                     ? LIBSSIG_OCSP_REVOKED
	                     : LIBSSIG_OCSP_UNKNOWN;
	result->reason = status == V_OCSP_CERTSTATUS_REVOKED ? reason : -1;
	result->valid = true;
	return LIBSSIG_OK;
}

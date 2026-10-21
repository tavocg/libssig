/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <libssig/time.h>
#include <stdint.h>
#include <string.h>

bool libssig_time_read(const ASN1_TIME* value, time_t* out_time) {
	ASN1_TIME* epoch = ASN1_TIME_new();
	int        days = 0, seconds = 0;
	bool       ok = epoch && ASN1_TIME_set_string(epoch, "19700101000000Z") &&
	          value && ASN1_TIME_diff(&days, &seconds, epoch, value);
	int64_t total = (int64_t)days * 86400 + seconds;
	ASN1_TIME_free(epoch);
	*out_time = (time_t)total;
	return ok && (int64_t)*out_time == total;
}

bool libssig_verify_time_parse(const char value[21], time_t* out_time) {
	if (strlen(value) != 20 || value[4] != '-' || value[7] != '-' ||
	    value[10] != 'T' || value[13] != ':' || value[16] != ':' ||
	    value[19] != 'Z') {
		return false;
	}

	char encoded[16];
	int  j = 0;
	for (int i = 0; i < 20; ++i) {
		if (i == 4 || i == 7 || i == 10 || i == 13 || i == 16) {
			continue;
		}
		encoded[j++] = value[i];
	}
	encoded[j] = 0;
	ASN1_TIME* parsed = ASN1_TIME_new();
	bool       ok = parsed && ASN1_TIME_set_string(parsed, encoded) &&
	          libssig_time_read(parsed, out_time);
	ASN1_TIME_free(parsed);
	return ok;
}

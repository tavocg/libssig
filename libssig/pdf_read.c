/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <libssig/pdf.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

static int hex_value(unsigned char c) {
	if (c >= '0' && c <= '9') {
		return c - '0';
	}
	if (c >= 'a' && c <= 'f') {
		return c - 'a' + 10;
	}
	if (c >= 'A' && c <= 'F') {
		return c - 'A' + 10;
	}
	return -1;
}
static bool hole_matches(
    const unsigned char* data,
    size_t               a,
    size_t               b,
    const unsigned char* contents,
    size_t               len
) {
	if (b <= a + 1 || data[a] != '<' || data[b - 1] != '>') {
		return false;
	}
	int    high = -1;
	size_t j = 0;
	for (size_t i = a + 1; i < b - 1; ++i) {
		unsigned char c = data[i];
		if (c == ' ' || c == '\n' || c == '\r' || c == '\t' || c == '\f' ||
		    c == 0) {
			continue;
		}
		int value = hex_value(c);
		if (value < 0) {
			return false;
		}
		if (high < 0) {
			high = value;
		} else {
			if (j >= len ||
			    contents[j++] != (unsigned char)((high << 4) | value)) {
				return false;
			}
			high = -1;
		}
	}
	return j == len && high < 0;
}
libssig_status libssig_pdf_signature_read(
    qpdf_data                    pdf,
    qpdf_oh                      dict,
    const libssig_verify_params* params,
    libssig_pdf_signature*       signature
) {
	qpdf_oh filter = qpdf_oh_get_key(pdf, dict, "/SubFilter");
	signature
	    ->timestamp = qpdf_oh_is_name_and_equals(pdf, filter, "/ETSI.RFC3161");
	if (!signature->timestamp &&
	    !qpdf_oh_is_name_and_equals(pdf, filter, "/ETSI.CAdES.detached")) {
		return LIBSSIG_ERROR_UNSUPPORTED;
	}
	qpdf_oh range = qpdf_oh_get_key(pdf, dict, "/ByteRange");
	if (!qpdf_oh_is_array(pdf, range) ||
	    qpdf_oh_get_array_n_items(pdf, range) != 4) {
		return LIBSSIG_ERROR_FORMAT;
	}
	size_t values[4];
	for (int i = 0; i < 4; ++i) {
		qpdf_oh   value = qpdf_oh_get_array_item(pdf, range, i);
		long long n = qpdf_oh_get_int_value(pdf, value);
		if (!qpdf_oh_is_integer(pdf, value) || n < 0 ||
		    (unsigned long long)n > params->data_len) {
			return LIBSSIG_ERROR_FORMAT;
		}
		values[i] = (size_t)n;
	}
	if (values[0] || values[1] >= values[2] ||
	    values[3] > params->data_len - values[2]) {
		return LIBSSIG_ERROR_FORMAT;
	}
	size_t      len = 0;
	const char* contents = qpdf_oh_get_binary_string_value(
	    pdf,
	    qpdf_oh_get_key(pdf, dict, "/Contents"),
	    &len
	);
	if (!contents || !len ||
	    !hole_matches(
	        params->data,
	        values[1],
	        values[2],
	        (const unsigned char*)contents,
	        len
	    )) {
		return LIBSSIG_ERROR_FORMAT;
	}
	signature->cms.data = malloc(len);
	if (!signature->cms.data) {
		return LIBSSIG_ERROR_MEMORY;
	}
	memcpy(signature->cms.data, contents, len);
	const unsigned char* cursor = signature->cms.data;
	long                 body = 0;
	int                  tag, cls;
	if (ASN1_get_object(&cursor, &body, &tag, &cls, (long)len) & 0x81 ||
	    tag != V_ASN1_SEQUENCE || cls != V_ASN1_UNIVERSAL || body < 0 ||
	    (size_t)body > len - (size_t)(cursor - signature->cms.data)) {
		return LIBSSIG_ERROR_FORMAT;
	}
	signature->cms.len = (size_t)(cursor - signature->cms.data) + (size_t)body;
	for (size_t i = signature->cms.len; i < len; ++i) {
		if (signature->cms.data[i]) {
			return LIBSSIG_ERROR_FORMAT;
		}
	}
	signature->content.len = values[1] + values[3];
	signature->content.data = malloc(
	    signature->content.len ? signature->content.len : 1
	);
	if (!signature->content.data) {
		return LIBSSIG_ERROR_MEMORY;
	}
	memcpy(signature->content.data, params->data, values[1]);
	memcpy(
	    signature->content.data + values[1],
	    params->data + values[2],
	    values[3]
	);
	signature->end = values[2] + values[3];
	signature->hole_start = values[1];
	signature->hole_end = values[2];
	return qpdf_has_error(pdf) ? LIBSSIG_ERROR_FORMAT : LIBSSIG_OK;
}

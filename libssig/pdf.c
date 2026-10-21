/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <libssig/pdf.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static size_t position(libssig_pdf_revision* r) {
	return (size_t)BIO_ctrl_pending(r->bytes);
}
static qpdf_oh copy_object(libssig_pdf_revision* r, qpdf_oh object) {
	if (qpdf_oh_is_array(r->pdf, object)) {
		qpdf_oh result = qpdf_oh_new_array(r->pdf);
		int     count = qpdf_oh_get_array_n_items(r->pdf, object);
		for (int i = 0; i < count; ++i) {
			qpdf_oh_append_item(
			    r->pdf,
			    result,
			    qpdf_oh_get_array_item(r->pdf, object, i)
			);
		}
		return result;
	}
	if (!qpdf_oh_is_dictionary(r->pdf, object)) {
		return 0;
	}
	qpdf_oh result = qpdf_oh_new_dictionary(r->pdf);
	qpdf_oh_begin_dict_key_iter(r->pdf, object);
	while (qpdf_oh_dict_more_keys(r->pdf)) {
		const char* key = qpdf_oh_dict_next_key(r->pdf);
		qpdf_oh     item = qpdf_oh_get_key(r->pdf, object, key);
		qpdf_oh_replace_key(r->pdf, result, key, item);
	}
	return result;
}
libssig_status libssig_pdf_open(
    const unsigned char*  data,
    size_t                len,
    libssig_pdf_revision* r
) {
	if (!data || len < 16 || len > INT_MAX || memcmp(data, "%PDF-", 5)) {
		return LIBSSIG_ERROR_FORMAT;
	}
	r->pdf = qpdf_init();
	r->bytes = BIO_new(BIO_s_mem());
	if (!r->pdf || !r->bytes) {
		return LIBSSIG_ERROR_MEMORY;
	}
	qpdf_silence_errors(r->pdf);
	qpdf_set_suppress_warnings(r->pdf, QPDF_TRUE);
	qpdf_set_attempt_recovery(r->pdf, QPDF_FALSE);
	if (qpdf_read_memory(r->pdf, "libssig PDF", (const char*)data, len, NULL) !=
	        QPDF_SUCCESS ||
	    qpdf_is_encrypted(r->pdf)) {
		return LIBSSIG_ERROR_UNSUPPORTED;
	}
	qpdf_oh   trailer = qpdf_get_trailer(r->pdf);
	long long size = qpdf_oh_get_int_value(
	    r->pdf,
	    qpdf_oh_get_key(r->pdf, trailer, "/Size")
	);
	if (size <= 0 || size > INT_MAX - 2048) {
		return LIBSSIG_ERROR_FORMAT;
	}
	r->first = r->next = (int)size;
	r->root = copy_object(r, qpdf_get_root(r->pdf));
	if (!r->root || qpdf_oh_has_key(r->pdf, r->root, "/Perms")) {
		return LIBSSIG_ERROR_UNSUPPORTED;
	}
	qpdf_oh extensions = qpdf_oh_get_key(r->pdf, r->root, "/Extensions");
	extensions = qpdf_oh_is_null(r->pdf, extensions)
	                 ? qpdf_oh_new_dictionary(r->pdf)
	                 : copy_object(r, extensions);
	if (!extensions) {
		return LIBSSIG_ERROR_FORMAT;
	}
	qpdf_oh_replace_key(
	    r->pdf,
	    extensions,
	    "/ESIC",
	    qpdf_oh_parse(r->pdf, "<< /BaseVersion /1.7 /ExtensionLevel 5 >>")
	);
	qpdf_oh_replace_key(r->pdf, r->root, "/Extensions", extensions);
	if (strcmp(qpdf_get_pdf_version(r->pdf), "1.7") < 0) {
		qpdf_oh_replace_key(
		    r->pdf,
		    r->root,
		    "/Version",
		    qpdf_oh_new_name(r->pdf, "/1.7")
		);
	}
	bool found = false;
	for (size_t i = len - 9; i > 0 && len - i <= 1024; --i) {
		if (memcmp(data + i, "startxref", 9)) {
			continue;
		}
		size_t j = i + 9;
		while (j < len && (data[j] == '\r' || data[j] == '\n' ||
		                   data[j] == ' ' || data[j] == '\t')) {
			++j;
		}
		size_t value = 0, begin = j;
		while (j < len && data[j] >= '0' && data[j] <= '9') {
			if (value > len / 10) {
				return LIBSSIG_ERROR_FORMAT;
			}
			value = value * 10 + data[j++] - '0';
		}
		if (j > begin && value < len) {
			r->previous = value;
			found = true;
		}
		break;
	}
	if (!found || qpdf_has_error(r->pdf) ||
	    BIO_write(r->bytes, data, (int)len) != (int)len ||
	    BIO_puts(r->bytes, "\n") <= 0) {
		return LIBSSIG_ERROR_FORMAT;
	}
	return LIBSSIG_OK;
}
void libssig_pdf_close(libssig_pdf_revision* r) {
	if (r->pdf) {
		qpdf_cleanup(&r->pdf);
	}

	BIO_free(r->bytes);
	*r = (libssig_pdf_revision){0};
}
static int object_begin(libssig_pdf_revision* r) {
	if (r->next - r->first >= 2048) {
		return 0;
	}
	int id = r->next++;
	qpdf_replace_object(r->pdf, id, 0, qpdf_oh_new_dictionary(r->pdf));
	r->offsets[id - r->first] = position(r);
	if (BIO_printf(r->bytes, "%d 0 obj\n", id) <= 0) {
		return 0;
	}
	return id;
}
int libssig_pdf_object(libssig_pdf_revision* r, const char* value) {
	int id = object_begin(r);
	if (!id || !value || BIO_puts(r->bytes, value) <= 0 ||
	    BIO_puts(r->bytes, "\nendobj\n") <= 0) {
		return 0;
	}
	return id;
}
int libssig_pdf_stream(
    libssig_pdf_revision* r,
    const unsigned char*  data,
    size_t                len
) {
	int id = object_begin(r);
	if (!id || len > INT_MAX ||
	    BIO_printf(r->bytes, "<< /Length %zu >>\nstream\n", len) <= 0 ||
	    BIO_write(r->bytes, data, (int)len) != (int)len ||
	    BIO_puts(r->bytes, "\nendstream\nendobj\n") <= 0) {
		return 0;
	}
	return id;
}
static qpdf_oh reference(libssig_pdf_revision* r, int id) {
	return qpdf_get_object_by_id(r->pdf, id, 0);
}
libssig_status libssig_pdf_slot(libssig_pdf_revision* r, bool timestamp) {
	int        id = object_begin(r);
	time_t     now = time(NULL);
	struct tm  utc;
	char       date[32];
	ASN1_TIME* generated = ASN1_TIME_set(NULL, now);
	bool       time_ok = generated && ASN1_TIME_to_tm(generated, &utc) &&
	               strftime(date, sizeof(date), "D:%Y%m%d%H%M%SZ", &utc);
	ASN1_TIME_free(generated);
	if (!id || !time_ok) {
		return LIBSSIG_ERROR_CRYPTO;
	}
	if (BIO_printf(
	        r->bytes,
	        "<< /Type /%s /Filter /Adobe.PPKLite /SubFilter /%s /M (%s) "
	        "/ByteRange ",
	        timestamp ? "DocTimeStamp" : "Sig",
	        timestamp ? "ETSI.RFC3161" : "ETSI.CAdES.detached",
	        date
	    ) <= 0) {
		return LIBSSIG_ERROR_CRYPTO;
	}
	r->range_offset = position(r);
	if (BIO_puts(
	        r->bytes,
	        "[0 00000000000000000000 00000000000000000000 "
	        "00000000000000000000] /Contents "
	    ) <= 0) {
		return LIBSSIG_ERROR_CRYPTO;
	}
	r->content_start = position(r);
	if (BIO_puts(r->bytes, "<") <= 0) {
		return LIBSSIG_ERROR_CRYPTO;
	}
	char zeros[1024];
	memset(zeros, '0', sizeof(zeros));
	for (int i = 0; i < 512; ++i) {
		if (BIO_write(r->bytes, zeros, sizeof(zeros)) != (int)sizeof(zeros)) {
			return LIBSSIG_ERROR_CRYPTO;
		}
	}
	if (BIO_puts(r->bytes, ">") <= 0) {
		return LIBSSIG_ERROR_CRYPTO;
	}
	r->content_end = position(r);
	if (BIO_puts(r->bytes, " >>\nendobj\n") <= 0) {
		return LIBSSIG_ERROR_CRYPTO;
	}
	char field[192];
	snprintf(
	    field,
	    sizeof(field),
	    "<< /Type /Annot /Subtype /Widget /Rect [0 0 0 0] /FT /Sig /T "
	    "(libssig-%d) /V %d 0 R >>",
	    id,
	    id
	);
	int     field_id = libssig_pdf_object(r, field);
	qpdf_oh form = qpdf_oh_get_key(r->pdf, r->root, "/AcroForm");
	form = qpdf_oh_is_null(r->pdf, form) ? qpdf_oh_new_dictionary(r->pdf)
	                                     : copy_object(r, form);
	if (!field_id || !form || qpdf_oh_has_key(r->pdf, form, "/XFA")) {
		return LIBSSIG_ERROR_UNSUPPORTED;
	}
	qpdf_oh fields = qpdf_oh_get_key(r->pdf, form, "/Fields");
	fields = qpdf_oh_is_null(r->pdf, fields) ? qpdf_oh_new_array(r->pdf)
	                                         : copy_object(r, fields);
	if (!qpdf_oh_is_array(r->pdf, fields)) {
		return LIBSSIG_ERROR_FORMAT;
	}
	qpdf_oh_append_item(r->pdf, fields, reference(r, field_id));
	qpdf_oh_replace_key(r->pdf, form, "/Fields", fields);
	qpdf_oh_replace_key(
	    r->pdf,
	    form,
	    "/SigFlags",
	    qpdf_oh_new_integer(r->pdf, 3)
	);
	int form_id = libssig_pdf_object(r, qpdf_oh_unparse_resolved(r->pdf, form));
	if (!form_id) {
		return LIBSSIG_ERROR_CRYPTO;
	}
	qpdf_oh_replace_key(r->pdf, r->root, "/AcroForm", reference(r, form_id));
	return qpdf_has_error(r->pdf) ? LIBSSIG_ERROR_FORMAT : LIBSSIG_OK;
}
libssig_status libssig_pdf_finish(
    libssig_pdf_revision* r,
    libssig_signature*    output
) {
	int root_id = libssig_pdf_object(
	    r,
	    qpdf_oh_unparse_resolved(r->pdf, r->root)
	);
	size_t xref = position(r);
	if (!root_id ||
	    BIO_printf(r->bytes, "xref\n%d %d\n", r->first, r->next - r->first) <=
	        0) {
		return LIBSSIG_ERROR_CRYPTO;
	}
	for (int i = r->first; i < r->next; ++i) {
		if (BIO_printf(
		        r->bytes,
		        "%010zu 00000 n \n",
		        r->offsets[i - r->first]
		    ) <= 0) {
			return LIBSSIG_ERROR_CRYPTO;
		}
	}
	if (BIO_printf(
	        r->bytes,
	        "trailer\n<< /Size %d /Root %d 0 R /Prev %zu "
	        ">>\nstartxref\n%zu\n%%%%EOF\n",
	        r->next,
	        root_id,
	        r->previous,
	        xref
	    ) <= 0) {
		return LIBSSIG_ERROR_CRYPTO;
	}
	char* data = NULL;
	long  len = BIO_get_mem_data(r->bytes, &data);
	if (len <= 0 || len > INT_MAX || qpdf_has_error(r->pdf)) {
		return LIBSSIG_ERROR_FORMAT;
	}
	if (r->content_end) {
		char range[128];
		int  count = snprintf(
            range,
            sizeof(range),
            "[0 %020zu %020zu %020zu]",
            r->content_start,
            r->content_end,
            (size_t)len - r->content_end
        );
		if (count != 66) {
			return LIBSSIG_ERROR_CRYPTO;
		}
		memcpy(data + r->range_offset, range, (size_t)count);
	}
	output->data = malloc((size_t)len);
	if (!output->data) {
		return LIBSSIG_ERROR_MEMORY;
	}
	memcpy(output->data, data, (size_t)len);
	output->len = (size_t)len;
	return LIBSSIG_OK;
}
libssig_status libssig_pdf_content(
    libssig_pdf_revision* r,
    libssig_signature*    output
) {
	char* data = NULL;
	long  len = BIO_get_mem_data(r->bytes, &data);
	if (!r->content_end || len <= 0 || (size_t)len < r->content_end) {
		return LIBSSIG_ERROR_FORMAT;
	}
	output->len = r->content_start + (size_t)len - r->content_end;
	output->data = malloc(output->len);
	if (!output->data) {
		return LIBSSIG_ERROR_MEMORY;
	}
	memcpy(output->data, data, r->content_start);
	memcpy(
	    output->data + r->content_start,
	    data + r->content_end,
	    (size_t)len - r->content_end
	);
	return LIBSSIG_OK;
}
libssig_status libssig_pdf_insert(
    libssig_pdf_revision*    r,
    const libssig_signature* token,
    libssig_signature*       output
) {
	if (token->len > (r->content_end - r->content_start - 2) / 2) {
		return LIBSSIG_ERROR_MEMORY;
	}
	char* bytes = NULL;
	BIO_get_mem_data(r->bytes, &bytes);
	const char* hex = "0123456789ABCDEF";
	for (size_t i = 0; i < token->len; ++i) {
		bytes[r->content_start + 1 + i * 2] = hex[token->data[i] >> 4];
		bytes[r->content_start + 2 + i * 2] = hex[token->data[i] & 15];
	}
	long len = BIO_get_mem_data(r->bytes, &bytes);
	output->data = malloc((size_t)len);
	if (!output->data) {
		return LIBSSIG_ERROR_MEMORY;
	}
	memcpy(output->data, bytes, (size_t)len);
	output->len = (size_t)len;
	return LIBSSIG_OK;
}
static libssig_status dss_array(
    libssig_pdf_revision*          r,
    qpdf_oh                        dss,
    const char*                    name,
    const libssig_validation_data* data,
    bool                           certificates
) {
	qpdf_oh array = qpdf_oh_get_key(r->pdf, dss, name);
	array = qpdf_oh_is_null(r->pdf, array) ? qpdf_oh_new_array(r->pdf)
	                                       : copy_object(r, array);
	if (!qpdf_oh_is_array(r->pdf, array)) {
		return LIBSSIG_ERROR_FORMAT;
	}
	int count = certificates ? sk_X509_num(data->certs)
	                         : sk_ASN1_TYPE_num(data->revocations);
	for (int i = 0; i < count; ++i) {
		unsigned char* encoded = NULL;
		int            len = 0;
		if (certificates) {
			len = i2d_X509(sk_X509_value(data->certs, i), &encoded);
		} else {
			ASN1_TYPE* value = sk_ASN1_TYPE_value(data->revocations, i);
			if (!strcmp(name, "/CRLs")) {
				if (value->type != V_ASN1_SEQUENCE) {
					continue;
				}
				len = i2d_ASN1_TYPE(value, &encoded);
			} else {
				if (value->type != V_ASN1_OTHER) {
					continue;
				}
				const unsigned char* cursor = ASN1_STRING_get0_data(
				    value->value.asn1_string
				);
				long remaining = ASN1_STRING_length(value->value.asn1_string),
				     body = 0;
				int tag, cls;
				if (ASN1_get_object(&cursor, &body, &tag, &cls, remaining) &
				    0x80) {
					return LIBSSIG_ERROR_FORMAT;
				}
				ASN1_OBJECT* oid = d2i_ASN1_OBJECT(NULL, &cursor, body);
				ASN1_OBJECT_free(oid);
				size_t offset = (size_t)(cursor - ASN1_STRING_get0_data(
				                                      value->value.asn1_string
				                                  ));
				len = (int)(remaining - (long)offset);
				encoded = OPENSSL_memdup(cursor, (size_t)len);
			}
		}
		int id = len > 0 && encoded
		             ? libssig_pdf_stream(r, encoded, (size_t)len)
		             : 0;
		OPENSSL_free(encoded);
		if (!id) {
			return LIBSSIG_ERROR_CRYPTO;
		}
		qpdf_oh_append_item(r->pdf, array, reference(r, id));
	}
	qpdf_oh_replace_key(r->pdf, dss, name, array);
	return qpdf_has_error(r->pdf) ? LIBSSIG_ERROR_FORMAT : LIBSSIG_OK;
}
libssig_status libssig_pdf_dss(
    libssig_pdf_revision*          r,
    const libssig_validation_data* data
) {
	qpdf_oh dss = qpdf_oh_get_key(r->pdf, r->root, "/DSS");
	dss = qpdf_oh_is_null(r->pdf, dss) ? qpdf_oh_new_dictionary(r->pdf)
	                                   : copy_object(r, dss);
	libssig_status status = dss_array(r, dss, "/Certs", data, true);
	if (status == LIBSSIG_OK) {
		status = dss_array(r, dss, "/OCSPs", data, false);
	}
	if (status == LIBSSIG_OK) {
		status = dss_array(r, dss, "/CRLs", data, false);
	}
	if (status == LIBSSIG_OK) {
		int id = libssig_pdf_object(r, qpdf_oh_unparse_resolved(r->pdf, dss));
		if (!id) {
			return LIBSSIG_ERROR_CRYPTO;
		}
		qpdf_oh_replace_key(r->pdf, r->root, "/DSS", reference(r, id));
	}
	return status;
}

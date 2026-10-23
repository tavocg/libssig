/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <libssig/libssig.h>
#include <math.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <qpdf/qpdf-c.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x)                                                               \
	do {                                                                       \
		if (!(x)) {                                                            \
			fprintf(stderr, "line %d: %s\n", __LINE__, #x);                    \
			return 1;                                                          \
		}                                                                      \
	} while (0)
libssig_status document_fixture_sign_pdf(
    EVP_PKEY*,
    X509*,
    libssig_sign_params,
    libssig_signature*,
    const libssig_pdf_appearance*
);

static BIO* pdf_create(int rotation, int unit) {
	BIO*   b = BIO_new(BIO_s_mem());
	size_t offsets[6];
	BIO_puts(b, "%PDF-1.7\n");
	offsets[1] = BIO_ctrl_pending(b);
	BIO_puts(
	    b,
	    "1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [] "
	    "/NeedAppearances true >> >>\nendobj\n"
	);
	offsets[2] = BIO_ctrl_pending(b);
	BIO_printf(
	    b,
	    "2 0 obj\n<< /Type /Pages /Count 2 /Kids [3 0 R 4 0 R] "
	    "/MediaBox [10 20 410 320] /CropBox [30 40 390 300] /Rotate %d "
	    ">>\nendobj\n",
	    rotation
	);
	offsets[3] = BIO_ctrl_pending(b);
	BIO_puts(
	    b,
	    "3 0 obj\n<< /Type /Page /Parent 2 0 R /Resources << >> >>\nendobj\n"
	);
	offsets[4] = BIO_ctrl_pending(b);
	BIO_printf(
	    b,
	    "4 0 obj\n<< /Type /Page /Parent 2 0 R /UserUnit %d /Resources << >> "
	    "/Annots [5 0 R] >>\nendobj\n",
	    unit
	);
	offsets[5] = BIO_ctrl_pending(b);
	BIO_puts(
	    b,
	    "5 0 obj\n<< /Type /Annot /Subtype /Text /Rect [35 45 40 50] /Contents "
	    "(existing) >>\nendobj\n"
	);
	size_t xref = BIO_ctrl_pending(b);
	BIO_puts(b, "xref\n0 6\n0000000000 65535 f \n");
	for (int i = 1; i < 6; ++i) {
		BIO_printf(b, "%010zu 00000 n \n", offsets[i]);
	}
	BIO_printf(
	    b,
	    "trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n%zu\n%%%%EOF\n",
	    xref
	);
	return b;
}

int main(int argc, char** argv) {
	CHECK(argc == 2);
	EVP_PKEY* key = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", 2048);
	X509*     cert = X509_new();
	CHECK(
	    key && cert && X509_set_version(cert, 2) && X509_set_pubkey(cert, key)
	);
	CHECK(ASN1_INTEGER_set(X509_get_serialNumber(cert), 1));
	CHECK(
	    X509_gmtime_adj(X509_getm_notBefore(cert), -60) &&
	    X509_gmtime_adj(X509_getm_notAfter(cert), 3600)
	);
	CHECK(X509_NAME_add_entry_by_txt(
	    X509_get_subject_name(cert),
	    "CN",
	    MBSTRING_ASC,
	    (const unsigned char*)"Appearance test",
	    -1,
	    -1,
	    0
	));
	CHECK(
	    X509_set_issuer_name(cert, X509_get_subject_name(cert)) &&
	    X509_sign(cert, key, EVP_sha256())
	);
	unsigned char pixels[] =
	    {255, 0, 0, 255, 0, 255, 0, 255, 0, 0, 255, 255, 0, 0, 0, 128};
	for (int rotation = 0; rotation < 360; rotation += 90) {
		for (int unit = 1; unit <= 2; ++unit) {
			BIO*                input = pdf_create(rotation, unit);
			char*               data;
			long                len = BIO_get_mem_data(input, &data);
			libssig_sign_params params = {
			    .data = (unsigned char*)data,
			    .data_len = (size_t)len,
			    .format = LIBSSIG_FORMAT_PADES,
			    .level = LIBSSIG_LEVEL_B_B
			};
			libssig_pdf_appearance a = {
			    .page_number = 2,
			    .x = 24,
			    .y = 36,
			    .width = 80,
			    .height = 40,
			    .pixels = pixels,
			    .pixel_width = 2,
			    .pixel_height = 2,
			    .row_stride = 8
			};
			libssig_signature output = {0};
			libssig_status    status = document_fixture_sign_pdf(
                key,
                cert,
                params,
                &output,
                &a
            );
			if (status) {
				fprintf(
				    stderr,
				    "rotation=%d unit=%d status=%d\n",
				    rotation,
				    unit,
				    status
				);
			}
			CHECK(status == LIBSSIG_OK);
			CHECK(
			    output.len > (size_t)len &&
			    !memcmp(data, output.data, (size_t)len)
			);
			libssig_verify_params verify = {
			    .data = output.data,
			    .data_len = output.len
			};
			libssig_verify_result result = {0};
			CHECK(
			    libssig_verify(&verify, &result) == LIBSSIG_OK &&
			    result.signature_valid
			);
			libssig_verify_free(&result);
			qpdf_data pdf = qpdf_init();
			CHECK(
			    qpdf_read_memory(
			        pdf,
			        "appearance",
			        (char*)output.data,
			        output.len,
			        NULL
			    ) == QPDF_SUCCESS
			);
			CHECK(qpdf_get_num_pages(pdf) == 2);
			qpdf_oh form = qpdf_oh_get_key(
			    pdf,
			    qpdf_get_root(pdf),
			    "/AcroForm"
			);
			CHECK(!qpdf_oh_get_bool_value(
			    pdf,
			    qpdf_oh_get_key(pdf, form, "/NeedAppearances")
			));
			qpdf_oh first = qpdf_get_page_n(pdf, 0),
			        page = qpdf_get_page_n(pdf, 1);
			CHECK(qpdf_oh_is_null(pdf, qpdf_oh_get_key(pdf, first, "/Annots")));
			qpdf_oh annotations = qpdf_oh_get_key(pdf, page, "/Annots");
			CHECK(qpdf_oh_get_array_n_items(pdf, annotations) == 2);
			CHECK(
			    qpdf_oh_get_object_id(
			        pdf,
			        qpdf_oh_get_array_item(pdf, annotations, 0)
			    ) == 5
			);
			qpdf_oh field = qpdf_oh_get_array_item(pdf, annotations, 1);
			CHECK(
			    qpdf_oh_get_object_id(pdf, qpdf_oh_get_key(pdf, field, "/P")) ==
			    4
			);
			qpdf_oh rect = qpdf_oh_get_key(pdf, field, "/Rect");
			double  width = qpdf_oh_get_numeric_value(
                               pdf,
                               qpdf_oh_get_array_item(pdf, rect, 2)
                           ) -
			               qpdf_oh_get_numeric_value(
			                   pdf,
			                   qpdf_oh_get_array_item(pdf, rect, 0)
			               );
			CHECK(fabs(width - (rotation % 180 ? 40.0 : 80.0) / unit) < 1e-6);
			CHECK(qpdf_oh_is_stream(
			    pdf,
			    qpdf_oh_get_key(pdf, qpdf_oh_get_key(pdf, field, "/AP"), "/N")
			));
			qpdf_cleanup(&pdf);
			char path[1024];
			snprintf(
			    path,
			    sizeof(path),
			    "%s/appearance-%d-%d.pdf",
			    argv[1],
			    rotation,
			    unit
			);
			FILE* file = fopen(path, "wb");
			CHECK(
			    file &&
			    fwrite(output.data, 1, output.len, file) == output.len &&
			    fclose(file) == 0
			);
			char* marker = NULL;
			for (size_t i = (size_t)len; i + 11 <= output.len; ++i) {
				if (!memcmp(output.data + i, "/Image Do Q", 11)) {
					marker = (char*)output.data + i;
					break;
				}
			}
			CHECK(marker);
			marker[1] = 'i';
			CHECK(
			    libssig_verify(&verify, &result) != LIBSSIG_OK ||
			    !result.signature_valid
			);
			libssig_verify_free(&result);
			libssig_signature_free(&output);
			a.page_number = 3;
			CHECK(
			    document_fixture_sign_pdf(key, cert, params, &output, &a) ==
			        LIBSSIG_ERROR_ARGUMENT &&
			    !output.data
			);
			a.page_number = 2;
			a.x = 10000;
			CHECK(
			    document_fixture_sign_pdf(key, cert, params, &output, &a) ==
			        LIBSSIG_ERROR_ARGUMENT &&
			    !output.data
			);
			a.x = NAN;
			CHECK(
			    document_fixture_sign_pdf(key, cert, params, &output, &a) ==
			        LIBSSIG_ERROR_ARGUMENT &&
			    !output.data
			);
			BIO_free(input);
		}
	}
	X509_free(cert);
	EVP_PKEY_free(key);
	return 0;
}

# Device inventory

`libssig_devices()` provides an owned snapshot of PKCS#11 modules, slots, tokens,
certificates and visible public/private/secret key metadata. The context may be
closed after the call. No module, session or object handles escape the API.

```c
libssig_context context = {0};
libssig_device_list devices = {0};
if (libssig_context_open(&context) == LIBSSIG_OK) {
    if (libssig_devices(&context, &devices, 0) == LIBSSIG_OK) {
        /* Iterate modules, slots, certificates and keys. */
    }
    libssig_context_close(&context);
}
libssig_devices_free(&devices);
```

Zero options includes hardware slots only, including empty readers. Software
slots are filtered before opening sessions or reading objects. Pass
`LIBSSIG_DEVICES_ALL` to include them. Existing `libssig_tokens()` remains
unchanged. Snapshots reuse `libssig_token` and `libssig_certificate_list`;
certificates now expose `public_key_bits` as well as their existing metadata.

Inspect module and slot `status`/`ck_rv` individually: a disconnected or failing
reader does not discard the other results. Allocation failures discard the new
snapshot. A nonempty output is rejected without modifying its existing data;
free it before reuse. All strings and arrays belong to the snapshot.

No login, PIN callback, signing operation, writable session or key-value read is
performed. Hidden attributes remain unavailable. A size inferred from a matching
certificate ID is marked `size_from_certificate`; it does not prove possession
or usability of a private key. Certificate metadata does not imply trust.

Use `libssig_devices_changed()` with a zero-initialized `libssig_device_state`
to poll without opening sessions or reading certificate objects. The first poll
reports a change. Subsequent calls compare slot presence and token identity,
and consume optional `C_WaitForSlotEvent(CKF_DONT_BLOCK)` notifications. Poll
with the same context and options, or reset the state when either changes.
Session counts, free memory and clocks do not trigger a reload. Events permit
detection of reinserting an otherwise identical card when supported by the
provider; metadata polling remains available when event support is absent.
The caller chooses the interval and synchronizes context closure/replacement.

PKCS#11 slot descriptions often identify a USB reader, but the API cannot
discover USB devices without a working provider or guarantee a physical USB
identity shared by multiple slots. Applications can group identical slot
descriptions within a module without conflating slot IDs from other modules.

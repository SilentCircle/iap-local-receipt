Description
===========

``iap_local_receipt`` is a Python library that supports Apple Local In-App
Purchase (IAP) receipt processing.

The library provides functions and classes to do the following.

- Verify the receipt signature against the Apple Root CA certificate and return
  the receipt as a binary ASN.1 blob.
- Extract the receipt and its (possibly multiple) in-app receipts from the
  binary ASN.1 blob.  The receipt is returned as a Python dictionary.
- Validate that the in-app receipts contain at least one receipt matching a
  given product id.  It can also optionally validate any or all of the bundle
  id, application version, and SHA-1 hash.

Recent Changes
--------------
- v0.2.0: Replaces ``M2Crypto`` with ``pyOpenSSL`` to validate the receipt's
  signature correctly. Thanks to Ilya Konstantantinov for the pull request.

Installation
============

To install ``iap_local_receipt`` you need:

- Python 2.5 or later in the 2.x line (earlier than 2.5 not tested).

If you have the dependencies, you have multiple options for installation:

- With pip (preferred), do `pip install iap_local_receipt`.
- With setuptools, do `easy_install iap_local_receipt`.
- To install the source, download it from
  `github <https://github.com/SilentCircle/iap-local-receipt>`_
  and run `python setup.py install`.

Usage
=====

The simplest possible usage is::

    from iap_local_receipt import IAPReceiptVerifier

    pkcs7_der = get_der_from_somewhere()
    (
        IAPReceiptVerifier(ca_cert_filename)
            .verify_and_parse(pkcs7_der)
            .validate('MY_AWESOME_PRODUCT')
    )

To do a full validation::

    from iap_local_receipt import IAPReceiptVerifier

    pkcs7_der = get_der_from_somewhere()
    (
        IAPReceiptVerifier(ca_cert_filename)
            .verify_and_parse(pkcs7_der)
            .validate('MY_AWESOME_PRODUCT',
                      bundle_id='com.example.AwesomeApp',
                      application_version='0',
                      guid='urn:uuid:'
                           '12345678-1234-5678-1234-567812345678')
    )

Note that the hex-format GUID provided *must* be prefixed with `urn:uuid` if it
contains dashes.  Alternatively, if the dashes are stripped out, the GUID may
be used as-is.

If validating a high volume of receipts, you may wish to instantiate the
validator separately::

    from iap_local_receipt import IAPReceiptVerifier

    verifier = IAPReceiptVerifier(ca_cert_filename)

    for pkcs7_der in lots_of_ders:
        (
            verifier.verify_and_parse(pkcs7_der)
                    .validate('MY_AWESOME_PRODUCT',
                              bundle_id='com.example.AwesomeApp',
                              application_version='0',
                              guid='urn:uuid:'
                                   '12345678-1234-5678-1234-567812345678')
        )

If something went wrong with the validation, you can get the receipt and raw
data from the verifier using the ``last_receipt()`` and ``last_receipt_der()``
member functions respectively.

Note that these may return ``None`` depending on where the failure occurred.

You can also choose to use the ``PKCS7Verifier``, ``IAPReceiptParser``, and
``IAPReceipt`` classes individually::

    from iap_local_receipt import PKCS7Verifier, IAPReceiptParser, IAPReceipt

    pkcs7_verifier = PKCS7Verifier(ca_cert_filename)
    receipt_parser = IAPReceiptParser()

    pkcs7_der = get_der_from_somewhere()

    receipt_der = pkcs7_verifier.verify_data(pkcs7_der)
    iap_receipt = receipt_parser.parse_app_receipt(receipt_der)
    iap_receipt.validate('MY_AWESOME_PRODUCT',
                          bundle_id='com.example.AwesomeApp',
                          application_version='0',
                          guid='urn:uuid:'
                               '12345678-1234-5678-1234-567812345678')

License
=======

``iap_local_receipt`` is distributed under the BSD license.


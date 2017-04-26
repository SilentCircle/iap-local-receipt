from OpenSSL import crypto
from cffi import FFI

ffi = FFI()


class PKCS7VerifyError(Exception):
    def __init__(self, message=None, **kwargs):
        super(PKCS7VerifyError, self).__init__(
            message or ffi.string(crypto._lib.ERR_error_string(crypto._lib.ERR_get_error(), ffi.NULL)),
            **kwargs
        )


class PKCS7Verifier:
    def __init__(self, root_ca_cert_file=None, root_ca_cert_string=None):
        self.store = None
        if root_ca_cert_file:
            self.load_ca_cert_file(root_ca_cert_file)
        elif root_ca_cert_string:
            self.load_ca_cert_string(root_ca_cert_string)

    def load_ca_cert_file(self, ca_cert_file):
        """
        Load a CA cert from a PEM file, replacing any previous cert.
        """
        self.load_ca_cert_string(open(ca_cert_file, 'rb').read())

    def load_ca_cert_string(self, ca_cert_string):
        """
        Load a CA cert from a PEM string, replacing any previous cert.
        """
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, ca_cert_string)
        self._load_cert(cert)

    def _load_cert(self, cert):
        self.store = crypto.X509Store()
        self.store.add_cert(cert)

    def verify_file(self, pkcs7_der_file, verify_time=None):
        """
        Verify signature on signed PKCS7 DER file.
        Return blob containing the signed data.
        Throw PKCS7VerifyError if verification failed.
        This will fail if the CA cert has not been loaded.
        """
        return self.verify_data(open(pkcs7_der_file, 'rb').read(), verify_time)

    def verify_data(self, pkcs7_der, verify_time=None):
        """
        Verify signature on signed PKCS7 DER blob.
        Return blob containing the signed data.
        Throw PKCS7VerifyError if verification failed.
        This will fail if the CA cert has not been loaded.
        """
        store = self.store or crypto.X509Store()
        if verify_time:
            store.set_time(verify_time)
        p7 = load_pkcs7_bio_der(pkcs7_der)
        out = crypto._new_mem_buf()
        if not crypto._lib.PKCS7_verify(p7._pkcs7, ffi.NULL, store._store, ffi.NULL, out, 0):
            raise PKCS7VerifyError()
        return crypto._bio_to_string(out)

    @staticmethod
    def get_data_without_certificate_verification(pkcs7_der):
        """
        Return blob containing the signed data without certificate chain verification (but with signature verification).
        Throw PKCS7VerifyError if signature verification failed.
        """
        p7 = load_pkcs7_bio_der(pkcs7_der)
        out = crypto._new_mem_buf()
        if not crypto._lib.PKCS7_verify(p7._pkcs7, ffi.NULL, ffi.NULL, ffi.NULL, out, crypto._lib.PKCS7_NOVERIFY):
            raise PKCS7VerifyError(crypto._lib.ERR_get_error())
        return crypto._bio_to_string(out)


def load_pkcs7_bio_der(p7_der):
    """
    Load a PKCS7 object from a PKCS7 DER blob.
    Return PKCS7 object.
    """
    try:
        return crypto.load_pkcs7_data(crypto.FILETYPE_ASN1, p7_der)
    except crypto.Error as ex:
        raise PKCS7VerifyError(ex)

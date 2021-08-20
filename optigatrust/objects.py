#!/usr/bin/env python
"""This module implements all Object manipulation related APIs of the optigatrust package """

from asn1crypto import x509 as asn1_x509
from asn1crypto import pem as asn1_pem

import optigatrust as optiga

__all__ = [
    'AppData',
    'AcquiredSession',
    'Session',
    'AESKey',
    'RSAKey',
    'ECCKey',
    'X509',
]


class AppData(optiga.Object):
    """
    A class used to represent an Application Data object on the OPTIGA Trust Chip.
    """


# pylint: disable=too-few-public-methods
class AcquiredSession:
    """
    A class used to represent a session object on the OPTIGA Trust Chip. This is a pseudo object,
    just to indicate to OPTIGA, that we would like to use the acquired session
    """
    def __init__(self):
        self.meta = None
        # pylint: disable=invalid-name
        self.id = 0x0000


# pylint: disable=too-few-public-methods
class Session:
    """
    A class used to represent a session object on the OPTIGA Trust Chip.
    """
    def __init__(self, key_id: int):
        self.meta = None
        # pylint: disable=invalid-name
        self.id = key_id


# pylint: disable=too-few-public-methods
class AESKey(optiga.Object):
    """
    A class used to represent an aes key object on the OPTIGA Trust Chip

    """
    def __init__(self):
        super().__init__(0xe200)


# pylint: disable=too-few-public-methods
class ECCKey(optiga.Object):
    """
    A class used to represent an ecc key object on the OPTIGA Trust Chip

    """
    def __init__(self, key_id: int):
        super().__init__(key_id)

        id_ref = self._optiga.key_id
        if key_id not in (id_ref.ECC_KEY_E0F0.value, id_ref.ECC_KEY_E0F1.value, id_ref.ECC_KEY_E0F2.value,
                          id_ref.ECC_KEY_E0F3.value) and key_id not in self._optiga.session_id_values:
            raise ValueError(
                'Your key_id {0} can\'t be sued to generate an ECC Key'.format(hex(key_id))
            )
        try:
            self.curve = self.meta['algorithm']
        except (KeyError, TypeError):
            pass


class RSAKey(optiga.Object):
    """
    A class used to represent an rsa key object on the OPTIGA Trust Chip

    """
    def __init__(self, key_id: int):
        if key_id not in (0xe0fc, 0xe0fd):
            raise ValueError(
                'key_id isn\'t supported should be either 0xe0fc, or 0xe0fd, you provided {0}'.format(hex(key_id))
            )
        self.key_size = None
        super().__init__(key_id)


def _append_length(data, last=False):
    data_with_length = bytearray(3)
    left = len(data)

    data_with_length[2] = left % 0x100

    left = left >> 8
    data_with_length[1] = left % 0x100

    if last:
        data_with_length[0] = 0xC0
    else:
        left = left >> 8
        data_with_length[0] = left % 0x100

    data_with_length.extend(data)

    return data_with_length


def _break_apart(string, sep, step):
    return sep.join(string[n:n + step] for n in range(0, len(string), step))


class X509(optiga.Object):
    """
    A class used to represent a certificate on the OPTIGA Trust Chip

    """

    def __init__(self, cert_id: int):
        """
        :param cert_id: One of supported object Ids assigned for certificates
        """
        super().__init__(cert_id)
        self._der = self._read()

    def __str__(self):
        header = "================== Certificate Object [{0}] ==================\n".format(hex(self.id))
        lcso = '{0:<30}:{1}\n'.format("Lifecycle State", self.meta['lcso'])
        size = '{0:<30}:{1}\n'.format("Size", self.meta['used_size'])
        read = '{0:<30}:{1}\n'.format("Access Condition: Read", self.meta['read'])
        change = '{0:<30}:{1}\n'.format("Access Conditions: Change", self.meta['change'])
        _pem = '{0:<30}:\n{1}\n'.format("PEM", str(self.pem).replace('\\n', '\n').replace('\\t', '\t'))
        cert = asn1_x509.Certificate.load(self.der)
        tbs_certificate = cert['tbs_certificate']
        issuer_cn = '{0:<30}:{1}\n'.format("Issuer: Common Name",
                                           tbs_certificate['issuer'].native['common_name'])
        subject_cn = '{0:<30}:{1}\n'.format("Subject: Common Name",
                                            tbs_certificate['subject'].native['common_name'])
        pkey = '{0:<30}:{1}\n'.format("Public Key", self.pkey)
        signature = '{0:<30}:{1}\n'.format("Signature", self.signature)
        footer = "============================================================"
        return header + lcso + size + read + change + _pem + issuer_cn + subject_cn + pkey + signature + footer

    @property
    def der(self):
        """
        This property allows to get or set the certificate in der form.
        Input should be a valid DER encoded certificate.
        """
        if self.updated:
            self._der = self._read()
        return self._der

    @der.setter
    def der(self, data: bytes or bytearray):
        self._update(data)

    @property
    def pem(self):
        """
        This property allows to get or set the certificate in PEM form.
        Input should be a valid PEM formatted certificate.
        """
        return asn1_pem.armor('CERTIFICATE', self.der)

    @pem.setter
    def pem(self, data: str):
        self._update(data)

    @property
    def pkey(self):
        """
        This property allows to get the public key from the certificate. In case the certificate can't be parsed an
        exception will be generated
        """
        try:
            cert = asn1_x509.Certificate.load(self.der)
            tbs_certificate = cert['tbs_certificate']
            subject_public_key_info = tbs_certificate['subject_public_key_info']
            subject_public_key = subject_public_key_info['public_key'].native.hex()

            return subject_public_key
        except TypeError as fail_to_parse:
            raise TypeError('Failed to parse the certificate. It\'s either empty or not supported.') from fail_to_parse

    @property
    def signature(self):
        """
        This property allows to get the signature of the certificate.
        In case the certificate can't be parsed an exception will be generated
        """
        try:
            cert = asn1_x509.Certificate.load(self.der)
            return cert['signature_value'].native.hex()
        except TypeError as fail_to_parse:
            raise TypeError('Failed to parse the certificate. It\'s either empty or not supported.') from fail_to_parse

    def _update(self, cert: str or bytes or bytearray):
        """
        This function writes a new certificate into the OPTIGA(TM) Trust device

        :param cert:
            Should be a a string with a PEM file with newlines separated or a bytes instance with DER encoded cert

        :raises:
            - ValueError - when any of the parameters contain an invalid value
            - TypeError - when any of the parameters are of the wrong type
            - OSError - when an error is returned by the core initialisation library
        """
        oids = self._optiga.object_id

        _supported_objects = (oids.IFX_CERT.value, oids.USER_CERT_1.value, oids.USER_CERT_2.value, oids.USER_CERT_3.value,
                              oids.TRUST_ANCHOR_1.value, oids.TRUST_ANCHOR_2.value,
                              oids.DATA_SLOT_1500B_0.value, oids.DATA_SLOT_1500B_1.value)
        if self.id not in _supported_objects:
            raise ValueError(
                'Object ID is not one of supported {0}'.format([hex(i) for i in _supported_objects])
            )

        if not isinstance(cert, str) and not isinstance(cert, bytes) and not isinstance(cert, bytearray):
            raise TypeError(
                'Bad certificate type should be either bytes, bytes string, or string'
            )

        if isinstance(cert, str):
            cert = str.encode(cert)

        _, _, der_cert = asn1_pem.unarmor(cert)

        if der_cert[0] != 0x30:
            raise ValueError(
                'Incorrect Certificate '
                'Should start with 0x30 your starts with {0}'.format(der_cert[0])
            )

        # Append tags
        # [len_byte_2, len_byte_1, len_byte_0] including the certificate and two lengths
        #   [len_byte_2, len_byte_1, len_byte_0] including the certificate and the length
        #       [len_byte_2, len_byte_1, len_byte_0]
        #           [der_encoded_certificate]
        # Write the result into the given Object ID
        l1_der_cert = _append_length(der_cert)
        l2_der_cert = _append_length(l1_der_cert)
        l3_der_cert = _append_length(l2_der_cert, last=True)

        # print("Certificate without encoding #1 {0}".format(list(der_cert)))
        # print("Certificate without encoding #2 {0}".format(list(l1_der_cert)))
        # print("Certificate without encoding #3 {0}".format(list(l2_der_cert)))
        # print("Certificate without encoding #4 {0}".format(list(l3_der_cert)))

        self.write(l3_der_cert)

        return l3_der_cert

    def _read(self, to_pem=False):
        """
        This function returns an existing certificate from the OPTIGA(TM) Trust device

        :param to_pem:
            A boolean flag to indicate, whether you want return certificate PEM encoded

        :raises:
            - ValueError - when any of the parameters contain an invalid value
            - TypeError - when any of the parameters are of the wrong type
            - OSError - when an error is returned by the core initialisation library

        :returns:
            A byte string with a PEM certificate or DER encoded byte string
        """
        oid = self._optiga.object_id

        if self.id not in self._optiga.object_id_values:
            raise ValueError(
                'Certificate Slot is not correct. '
                'Supported values are {0} class you used {1}'.format(self._optiga.object_id_values, self.id)
            )
        _supported_objects = (oid.IFX_CERT.value, oid.USER_CERT_1.value, oid.USER_CERT_2.value, oid.USER_CERT_3.value,
                              oid.TRUST_ANCHOR_1.value, oid.TRUST_ANCHOR_2.value,
                              oid.DATA_SLOT_1500B_0.value, oid.DATA_SLOT_1500B_1.value)
        if self.id not in _supported_objects:
            raise ValueError(
                'Object ID is not one of supported {0}'.format([hex(i) for i in _supported_objects])
            )

        der_cert = self.read()

        # print(list(der_cert))

        if len(der_cert) == 0:
            raise ValueError(
                'Certificate Slot {0} is empty'.format(self.id)
            )

        # OPTIGA Trust Code to tag an X509 certificate
        if der_cert[0] == 0xC0:
            der_cert = der_cert[9:]

        if to_pem:
            return asn1_pem.armor('CERTIFICATE', der_cert)
        return bytes(der_cert)

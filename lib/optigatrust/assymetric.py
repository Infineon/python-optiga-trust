# ============================================================================
# The MIT License
# 
# Copyright (c) 2018 Infineon Technologies AG
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE
# ============================================================================
from ctypes import *
import warnings
import hashlib

from optigatrust import ctrl
from optigatrust.const import x, m1, m3, charge

__all__ = [
    'EccKey',
    'RsaKey',
    'ecc_generate_keypair',
    'EcdsaSignature',
    'RsassaSignature',
    'ecdsa_sign',
    'rsa_pkcs1v1_sign'
]


def _str2curve(optiga, curve_str, return_value=False):
    if curve_str == 'secp256r1' or curve_str == 'nestp256r1':
        c = optiga.curves.NIST_P_256
    elif curve_str == 'secp384r1' or curve_str == 'nestp384r1':
        c = optiga.curves.NIST_P_384
    elif curve_str == 'secp521r1' or curve_str == 'nestp512r1':
        c = optiga.curves.NIST_P_521
    elif curve_str == 'brainpool256r1':
        c = optiga.curves.BRAINPOOL_P256R1
    elif curve_str == 'brainpoolp384r1':
        c = optiga.curves.BRAINPOOL_P384R1
    elif curve_str == 'brainpoolp512r1':
        c = optiga.curves.BRAINPOOL_P512R1
    else:
        raise ValueError('Curve not supported use one of these: secp256r1/nestp256r1, secp384r1/nestp384r1, '
                         'secp521r1/nestp512r1, brainpool256r1, brainpoolp384r1, brainpoolp512r1')

    if return_value:
        return c.value
    else:
        return c


class _Key:
    def __init__(self, pkey: bytes, keyid: int, algorithm: str, key_usage):
        self._pkey = pkey
        self._keyid = keyid
        self._key_usage = key_usage
        self._algorithm = algorithm

    @property
    def pkey(self):
        return self._pkey

    @property
    def keyid(self):
        return self._keyid

    @property
    def key_usage(self):
        return self._key_usage

    @property
    def algorithm(self):
        return self._algorithm


class _Signature:
    def __init__(self, hash_alg: str, keyid: int, signature: bytes, algorithm: str):
        self._hash_alg = hash_alg
        self._keyid = keyid
        self._signature = signature
        self._algorithm = algorithm

    @property
    def hash_alg(self):
        return self._hash_alg

    @property
    def keyid(self):
        return self._keyid

    @property
    def signature(self):
        return self._signature

    @property
    def algorithm(self):
        return self._algorithm


class EccKey(_Key):
    def __init__(self, pkey, keyid, curve, key_usage):
        super().__init__(pkey, keyid, 'ec', key_usage)

        allowed_curves = {'secp256r1', 'secp384r1'}
        if curve not in allowed_curves:
            raise ValueError("Supported curves {0} you provided {1}".format(allowed_curves, curve))
        self._curve = curve

    @property
    def curve(self):
        return self._curve


def ecc_generate_keypair(curve='secp256r1', keyid=0xe0f1, key_usage=None):
    """
    This function generates an ECC keypair, the private part is stored on the chip based on the provided slot

    :param curve:
        Curve name, should be either secp256r1 or secp384r1

    :param keyid:
        A Private Key Slot object ID.

    :param key_usage:
        A key usage indicator. The value should be the KeyUsage Enumeration. By default
        [KeyUsage.KEY_AGREEMENT, KeyUsage.AUTHENTICATION]

    :raises
        TypeError - when any of the parameters are of the wrong type
        OSError - when an error is returned by the chip initialisation library

    :return:
        EccKey object or None
    """
    _bytes = None
    optiga = ctrl.init_optiga()
    api = optiga.api

    if key_usage is None:
        key_usage = [optiga.key_usage.KEY_AGREEMENT, optiga.key_usage.AUTHENTICATION]

    c = _str2curve(optiga, curve, return_value=True)
    if c not in optiga.curves_values:
        raise TypeError(
            "object_id not found. \n\r Supported = {0},\n\r  Provided = {1}".format(list(optiga.curves_values), c))

    api.exp_optiga_crypt_ecc_generate_keypair.argtypes = c_int, c_ubyte, c_bool, c_void_p, POINTER(c_ubyte), POINTER(
        c_ushort)
    api.exp_optiga_crypt_ecc_generate_keypair.restype = c_int

    c_keyusage = c_ubyte(sum(map(lambda ku: ku.value, key_usage)))
    c_keyid = c_ushort(keyid)
    p = (c_ubyte * 100)()
    c_plen = c_ushort(len(p))

    ret = api.exp_optiga_crypt_ecc_generate_keypair(c, c_keyusage, 0, byref(c_keyid), p, byref(c_plen))

    pubkey = (c_ubyte * c_plen.value)()
    memmove(pubkey, p, c_plen.value)

    if ret == 0:
        return EccKey(pkey=bytes(pubkey), keyid=keyid, curve=curve, key_usage=key_usage)
    else:
        warnings.warn("Failed to generate an ECC keypair, return a NoneType")
        return None


class EcdsaSignature(_Signature):
    def __init__(self, hash_alg, keyid, signature):
        signature_algorithm_id = '%s_%s' % (hash_alg, 'ecdsa')
        super().__init__(hash_alg, keyid, signature, signature_algorithm_id)


def ecdsa_sign(ecc_key: EccKey, data: bytes or bytearray or str):
    """
    This function signs given data based on the provided EccKey object

    :param ecc_key:
        a valid EccKey object. Use ecc.generate_keypair() for this

    :param data:
        Data to sign, the data will be hashed based on the used curve. If secp256r1 then sha256, otherwise sha384

    :raises:
        TypeError - when any of the parameters are of the wrong type
        OSError - when an error is returned by the chip initialisation library

    :return:
        EcdsaSignature object or None
    """
    api = ctrl.init()

    if not isinstance(data, bytes) and not isinstance(data, bytearray):
        if isinstance(data, str):
            _d = bytes(data.encode())
            warnings.warn("data will be converted to bytes type before signing")
        else:
            raise TypeError('Data to sign should be either bytes or str type, you gave {0}'.format(type(data)))
    else:
        _d = data

    if not isinstance(ecc_key, EccKey):
        raise TypeError('Key ID should be selected of class KeyId')

    api.exp_optiga_crypt_ecdsa_sign.argtypes = POINTER(c_ubyte), c_ubyte, c_ushort, POINTER(c_ubyte), POINTER(c_ubyte)
    api.exp_optiga_crypt_ecdsa_sign.restype = c_int

    if ecc_key.curve == 'secp256r1':
        digest = (c_ubyte * 32)(*hashlib.sha256(_d).digest())
        s = (c_ubyte * (64 + 6))()
        hash_algorithm = 'sha256'
    elif ecc_key.curve == 'secp384r1':
        digest = (c_ubyte * 48)(*hashlib.sha384(_d).digest())
        s = (c_ubyte * (96 + 6))()
        hash_algorithm = 'sha384'
    else:
        digest = (c_ubyte * 0)(*hashlib.sha256(_d).digest())
        s = (c_ubyte * 0)()
        hash_algorithm = 'None'
    c_slen = c_ubyte(len(s))

    ret = api.exp_optiga_crypt_ecdsa_sign(digest, len(digest), ecc_key.keyid, s, byref(c_slen))

    if ret == 0:
        signature = (c_ubyte * (c_slen.value + 2))()
        signature[0] = 0x30
        signature[1] = c_slen.value
        memmove(addressof(signature) + 2, s, c_slen.value)

        return EcdsaSignature(hash_algorithm, ecc_key.keyid, bytes(signature))
    else:
        warnings.warn("Failed to sign a data, return a NoneType")
        return None


class RsaKey(_Key):
    def __init__(self, pkey: bytes, keyid: int, key_size: int, key_usage):
        super().__init__(pkey, keyid, 'rsa', key_usage)

        allowed_key_sizes = {1024, 2048}
        if key_size not in allowed_key_sizes:
            raise ValueError("Supported key sizes {0} you provided {1}".format(allowed_key_sizes, key_size))
        self._key_size = key_size

    @property
    def key_size(self):
        return self._key_size


def rsa_generate_keypair(key_size='1024', keyid=0xe0fc, key_usage=None):
    """
    This function generates an RSA keypair, the private part is stored on the chip based on the provided slot

    :param key_size:
        Size of the key, can be 1024 or 2048

    :param keyid:
        A Private Key Slot object ID. The value should be within the KeyId Enumeration

    :param key_usage:
        A key usage indicator. The value should be the KeyUsage Enumeration. By default
        [KeyUsage.KEY_AGREEMENT, KeyUsage.AUTHENTICATION]

    :raises:
        TypeError - when any of the parameters are of the wrong type
        OSError - when an error is returned by the chip initialisation library

    :return:
        RsaKey object or None
    """
    _bytes = None
    optiga = ctrl.init_optiga()
    api = optiga.api

    if key_usage is None:
        key_usage = [optiga.key_usage.KEY_AGREEMENT, optiga.key_usage.AUTHENTICATION, optiga.key_usage.ENCRYPTION]

    allowed_key_sizes = {'1024', '2048'}
    if key_size not in allowed_key_sizes:
        raise ValueError('This key size is not supported, you typed {0} (type {1}) supported are [1024, 2048]'.
                         format(key_size, type(key_size)))

    if keyid not in optiga.key_id_values:
        raise TypeError(
            "object_id not found. \n\r Supported = {0},\n\r  Provided = {1}".format(list(optiga.key_id_values), keyid))

    api.exp_optiga_crypt_rsa_generate_keypair.argtypes = c_int, c_ubyte, c_bool, c_void_p, POINTER(c_ubyte), POINTER(
        c_ushort)
    api.exp_optiga_crypt_rsa_generate_keypair.restype = c_int

    if key_size is '1024':
        c_keytype = 0x41
        rsa_header = b'\x30\x81\x9F\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01\x05\x00'
    else:
        c_keytype = 0x42
        rsa_header = b'\x30\x82\x01\x22\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00'

    c_keyusage = c_ubyte(sum(map(lambda ku: ku.value, key_usage)))
    c_keyid = c_ushort(keyid)
    p = (c_ubyte * 320)()
    c_plen = c_ushort(len(p))

    ret = api.exp_optiga_crypt_ecc_generate_keypair(c_keytype, c_keyusage, 0, byref(c_keyid), p, byref(c_plen))

    pubkey = (c_ubyte * c_plen.value)()
    memmove(pubkey, p, c_plen.value)

    if ret == 0:
        return RsaKey(pkey=rsa_header + bytes(pubkey), keyid=keyid, key_size=int(key_size), key_usage=key_usage)
    else:
        raise ValueError('Failed to generate an RSA keypair, return a NoneType')


class RsassaSignature(_Signature):
    def __init__(self, hash_alg, keyid, signature):
        signature_algorithm_id = '%s_%s' % (hash_alg, 'rsa')
        super().__init__(hash_alg, keyid, signature, signature_algorithm_id)


def rsa_pkcs1v1_sign(rsa_key: RsaKey, data: bytes or bytearray or str, hash_algorithm='sha256'):
    """
    This function signs given data based on the provided RsaKey object

    :param rsa_key:
        a valid RsaKey object. Use rsa.generate_keypair() for this

    :param data:
        Data to sign

    :param hash_algorithm:
        Hash algorithm which should be used to sign data. SHA256 by default

    :raises:
        TypeError - when any of the parameters are of the wrong type
        OSError - when an error is returned by the chip initialisation library

    :return:
        RsassaSignature object or None
    """
    api = ctrl.init()

    if not ctrl.is_trustm():
        raise TypeError('You are trying to use Trust M API with the Trust X hardware')

    if not isinstance(data, bytes) and not isinstance(data, bytearray):
        if isinstance(data, str):
            _d = bytes(data.encode())
            warnings.warn("data will be converted to bytes type before signing")
        else:
            raise TypeError('Data to sign should be either bytes or str type, you gave {0}'.format(type(data)))
    else:
        _d = data

    if not isinstance(rsa_key, RsaKey):
        raise TypeError('Key ID should be selected of class KeyId')

    api.optiga_crypt_rsa_sign.argtypes = POINTER(c_ubyte), c_ubyte, c_ushort, POINTER(c_ubyte), POINTER(c_ubyte)
    api.optiga_crypt_rsa_sign.restype = c_int

    if hash_algorithm == 'sha256':
        digest = (c_ubyte * 32)(*hashlib.sha256(_d).digest())
        s = (c_ubyte * 320)()
        # Signature schemes RSA SSA PKCS1-v1.5 with SHA256 digest
        sign_scheme = 0x01
    elif hash_algorithm == 'sha384':
        digest = (c_ubyte * 48)(*hashlib.sha384(_d).digest())
        s = (c_ubyte * 320)()
        # Signature schemes RSA SSA PKCS1-v1.5 with SHA384 digest
        sign_scheme = 0x02
    else:
        raise ValueError('This key isze is not supported, you typed {0} supported are [\'sha256\', \'sha384\']'
                         .format(hash_algorithm))
    c_slen = c_uint(len(s))

    ret = api.exp_optiga_crypt_rsa_sign(sign_scheme, digest, len(digest), rsa_key.keyid, s, byref(c_slen), 0)

    if ret == 0:
        signature = (c_ubyte * c_slen.value)()
        memmove(addressof(signature), s, c_slen.value)
        print(bytes(signature))
        return RsassaSignature(hash_algorithm, rsa_key.keyid, bytes(signature))
    else:
        warnings.warn("Failed to sign a data, return a NoneType")
        return None

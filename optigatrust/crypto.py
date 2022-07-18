#!/usr/bin/env python
"""This module implements all crypo related APIs of the optigatrust package """

from ctypes import c_ubyte, c_ushort, c_byte, c_int, c_bool, c_void_p, byref, \
    POINTER, Structure, memmove, addressof, c_uint
import warnings
import hashlib

# Optiga doesn't produce the whole public key, to which other platforms used to.
# We use an asn1 engine to append this info
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

import optigatrust as optiga
from optigatrust import objects

__all__ = [
    'random',
    'generate_pair',
    'ecdsa_sign',
    'ecdh',
    'pkcs1v15_encrypt',
    'pkcs1v15_decrypt',
    'pkcs1v15_sign',
    'hmac',
    'tls_prf',
    'hkdf',
    'ECDSASignature',
    'PKCS1v15Signature',
]

curves_map = {
    'secp256r1': optiga.enums.m3.Curves.SEC_P256R1,
    'secp384r1': optiga.enums.m3.Curves.SEC_P384R1,
    'secp521r1': optiga.enums.m3.Curves.SEC_P521R1,
    'brainpoolp256r1': optiga.enums.m3.Curves.BRAINPOOL_P256R1,
    'brainpoolp384r1': optiga.enums.m3.Curves.BRAINPOOL_P384R1,
    'brainpoolp512r1': optiga.enums.m3.Curves.BRAINPOOL_P512R1
}


def _str2curve(curve_str, return_value=False):
    global curves_map

    if curve_str in curves_map:
        if return_value:
            return curves_map[curve_str].value
        return curves_map[curve_str]
    raise ValueError('Your curve ({0}) not supported use one of these: {1}'.format(curve_str, curves_map.keys()))


def _curve2str(curve):
    global curves_map

    for entry in curves_map:
        if curve == curves_map[entry]:
            return entry

    raise ValueError('Your curve ({0}) not supported use one of these: {1}'.format(curve, curves_map.keys()))


def _native_to_pkcs(pkey, key=None, algorithm=None):
    """
    OPTIGA doesnt use and accept key information as part of the imput, so we need to append it after key_generation
    or strip for input

    :param pkey:
        a bytestring with the public key from OPTIGA

    :param key:
        A bytestring with key value from OPTIGA

    :param algorithm:
        A unicode string for an algorithm.

    :raises:
        - ValueError - when any of the parameters are not expected
        - TypeError - when any of the parameters are of the wrong type
        - OSError - when an error is returned by the core initialisation library

    :returns:
        A tuple of keys (public_key, private_key)
    """
    _algorithms_map = {
        'secp256r1':
            ('ec', b'0Y0\x13\x06\x07*\x86H\xce=\x02\x01\x06\x08*\x86H\xce=\x03\x01\x07', ec.SECP256R1()),
        'secp384r1':
            ('ec', b'0v0\x10\x06\x07*\x86H\xce=\x02\x01\x06\x05+\x81\x04\x00"', ec.SECP384R1()),
        'secp521r1':
            ('ec', b'0\x81\x9b0\x10\x06\x07*\x86H\xce=\x02\x01\x06\x05+\x81\x04\x00#', ec.SECP521R1()),
        'brainpoolp256r1':
            ('ec', b'0Z0\x14\x06\x07*\x86H\xce=\x02\x01\x06\t+$\x03\x03\x02\x08\x01\x01\x07', ec.BrainpoolP256R1()),
        'brainpoolp384r1':
            ('ec', b'0z0\x14\x06\x07*\x86H\xce=\x02\x01\x06\t+$\x03\x03\x02\x08\x01\x01\x0b', ec.BrainpoolP384R1()),
        'brainpoolp512r1':
            ('ec', b'0\x81\x9b0\x14\x06\x07*\x86H\xce=\x02\x01\x06\t+$\x03\x03\x02\x08\x01\x01\r', ec.BrainpoolP512R1())
    }
    if algorithm not in _algorithms_map:
        raise ValueError(
            '{0} isn\'t supported. Use one of {1}'.format(algorithm, _algorithms_map.keys())
        )
    if not isinstance(pkey, (bytes, bytearray)):
        raise TypeError(
            'pkey is of unsupported types (pkey type = {0}), '
            'should be either bytes or bytearray'.format(type(pkey))
        )
    if key is not None and not isinstance(key, (bytes, bytearray)):
        raise TypeError(
            'key is of unsupported types (key type = {0}), '
            'should be either bytes or bytearray'.format(type(key))
        )
    _type = _algorithms_map[algorithm][0]
    if _type == 'ec':
        prefix = _algorithms_map[algorithm][1]
        pyca_curve = _algorithms_map[algorithm][2]
        public_key = prefix + pkey
        if key is not None:
            private_key = ec.derive_private_key(int.from_bytes(key[2:], 'big'), pyca_curve, default_backend())
            private_key = private_key.private_bytes(encoding=serialization.Encoding.DER,
                                                    format=serialization.PrivateFormat.PKCS8,
                                                    encryption_algorithm=serialization.NoEncryption())
        else:
            private_key = None
        return public_key, private_key
    return None, None


def _pkcs_to_native(pkey, algorithm=None):
    """
    OPTIGA doesnt use and accept key information as part of the imput, so we need to append it after key_generation
    or strip for input

    :param pkey:
        a bytestring with the public key aimed to OPTIGA

    :param algorithm:
        A unicode string for an algorithm.

    :raises:
        - ValueError - when any of the parameters are not expected
        - TypeError - when any of the parameters are of the wrong type
        - OSError - when an error is returned by the core initialisation library

    :returns:
        Public key as two DER Octet Strings
    """
    _algorithms_map = {
        'secp256r1': 23,
        'secp384r1': 20,
        'secp521r1': 21,
        'brainpoolp256r1': 24,
        'brainpoolp384r1': 24,
        'brainpoolp512r1': 25
    }
    if algorithm not in _algorithms_map:
        raise ValueError(
            '{0} isn\'t supported. Use one of {1}'.format(algorithm, _algorithms_map.keys())
        )
    if not isinstance(pkey, (bytes, bytearray)):
        raise TypeError(
            'pkey is of unsupported types (pkey type = {0}), '
            'should be either bytes or bytearray'.format(type(pkey))
        )
    prefix_length = _algorithms_map[algorithm]

    return pkey[prefix_length:]


# pylint: disable=missing-class-docstring disable=too-few-public-methods
class PublicKeyFromHost(Structure):
    _fields_ = [("public_key", POINTER(c_ubyte)),
                ("length", c_ushort),
                ("key_type", c_ubyte)]


# pylint: disable=too-few-public-methods
class _Signature:
    def __init__(self, hash_alg: str, key_id: int, signature: bytes, algorithm: str):
        self.hash_alg = hash_alg
        self.key_id = key_id
        self.signature = signature
        self.algorithm = algorithm


# pylint: disable=too-few-public-methods
class ECDSASignature(_Signature):
    def __init__(self, hash_alg, key_id, signature):
        signature_algorithm_id = '%s_%s' % (hash_alg, 'ecdsa')
        super().__init__(hash_alg, key_id, signature, signature_algorithm_id)


# pylint: disable=too-few-public-methods
class PKCS1v15Signature(_Signature):
    def __init__(self, hash_alg, keyid, signature):
        signature_algorithm_id = '%s_%s' % (hash_alg, 'rsa')
        super().__init__(hash_alg, keyid, signature, signature_algorithm_id)


def random(number, trng=True):
    """
    This function generates a random number

    :param number:
        how much randomness to generate. Valid values are integers from 8 to 256

    :param trng:
        If True the a True Random Generator will be used, otherwise Deterministic Random Number Generator

    :raises:
        - TypeError - when any of the parameters are of the wrong type
        - OSError - when an error is returned by the chip initialisation library

    :returns:
        Bytes object with randomness
    """
    chip = optiga.Chip()
    api = chip.api

    api.exp_optiga_crypt_random.argtypes = c_byte, POINTER(c_ubyte), c_ushort
    api.exp_optiga_crypt_random.restype = c_int
    ptr = (c_ubyte * number)()

    if trng is True:
        ret = api.exp_optiga_crypt_random(chip.rng.TRNG.value, ptr, len(ptr))
    else:
        ret = api.exp_optiga_crypt_random(chip.rng.DRNG.value, ptr, len(ptr))

    if ret == 0:
        return bytes(ptr)
    return bytes(0)


# pylint: disable=too-many-locals
def _generate_ecc_pair(key_object, curve, key_usage=None, export=False):
    opt = optiga.Chip()
    _allowed_key_usage = {
        'key_agreement': opt.key_usage.KEY_AGR,
        'authentication': opt.key_usage.AUTH,
        'signature': opt.key_usage.SIGN
    }
    _key_sizes = {
        'secp256r1': (68, 34),
        'secp384r1': (100, 50),
        'secp521r1': (137, 67),
        'brainpoolp256r1': (68, 34),
        'brainpoolp384r1': (100, 50),
        'brainpoolp512r1': (133, 66)
    }
    _key_usage = list()
    priv_key = None
    if key_usage is None:
        _key_usage = [opt.key_usage.KEY_AGR, opt.key_usage.SIGN]
    else:
        for entry in key_usage:
            if entry not in _allowed_key_usage:
                raise ValueError(
                    'Wrong Key Usage value {0}, supported are {1}'.format(entry, _allowed_key_usage.keys())
                )
            _key_usage.append(_allowed_key_usage[entry])

    _curve = _str2curve(curve, return_value=True)
    if _curve not in opt.curves_values:
        raise TypeError(
            "object_id not found. \n\r Supported = {0},\n\r  "
            "Provided = {1}".format(map(_curve2str,list(opt.curves), curve)))

    c_keyusage = c_ubyte(sum(map(lambda ku: ku.value, _key_usage)))
    pkey = (c_ubyte * _key_sizes[curve][0])()
    c_plen = c_ushort(len(pkey))

    if export:
        # https://github.com/Infineon/optiga-trust-m/wiki/Data-format-examples#RSA-Private-Key
        key = (c_ubyte * _key_sizes[curve][1])()
    else:
        key = byref(c_ushort(key_object.id))

    ret = opt.api.exp_optiga_crypt_ecc_generate_keypair(_curve, c_keyusage, int(export), key, pkey, byref(c_plen))

    if export:
        priv_key = (c_ubyte * _key_sizes[curve][1])()
        memmove(priv_key, key, _key_sizes[curve][1])
        pub_key = (c_ubyte * c_plen.value)()
        memmove(pub_key, pkey, c_plen.value)
    else:
        pub_key = (c_ubyte * c_plen.value)()
        memmove(pub_key, pkey, c_plen.value)

    if ret == 0:
        key_object.curve = curve
        if export:
            public_key, private_key = _native_to_pkcs(key=bytes(priv_key), pkey=bytes(pub_key), algorithm=curve)
            return public_key, private_key

        public_key, _ = _native_to_pkcs(key=None, pkey=bytes(pub_key), algorithm=curve)
        return public_key, None

    raise IOError('Function can\'t be executed. Error {0}'.format(hex(ret)))


# pylint: disable=too-many-locals disable=too-many-branches
def _generate_rsa_pair(key_object, key_size=1024, key_usage=None, export=False):
    handle = optiga.Chip()
    _allowed_key_usages = {
        'key_agreement': handle.key_usage.KEY_AGR,
        'authentication': handle.key_usage.AUTH,
        'encryption': handle.key_usage.ENCRYPT,
        'signature': handle.key_usage.SIGN
    }
    _key_usage = list()
    priv_key = None
    if key_usage is None:
        _key_usage = [handle.key_usage.KEY_AGR, handle.key_usage.SIGN]
    else:
        for entry in key_usage:
            if entry not in _allowed_key_usages:
                raise ValueError(
                    'Wrong Key Usage value {0}, supported are {1}'.format(entry, _allowed_key_usages.keys())
                )
            _key_usage.append(_allowed_key_usages[entry])

    api = handle.api

    allowed_key_sizes = (1024, 2048)
    if key_size not in allowed_key_sizes:
        raise ValueError('This key size is not supported, you typed {0} (type {1}) supported are [1024, 2048]'.
                         format(key_size, type(key_size)))

    api.exp_optiga_crypt_rsa_generate_keypair.argtypes = c_int, c_ubyte, c_bool, c_void_p, POINTER(
        c_ubyte), POINTER(c_ushort)
    api.exp_optiga_crypt_rsa_generate_keypair.restype = c_int

    if key_size == 1024:
        c_keytype = 0x41
        rsa_header = b'0\x81\x9f0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x01\x05\x00'
    else:
        c_keytype = 0x42
        rsa_header = b'0\x82\x01"0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x01\x05\x00'

    c_keyusage = c_ubyte(sum(map(lambda ku: ku.value, _key_usage)))

    pkey = (c_ubyte * 320)()
    if export:
        # https://github.com/Infineon/optiga-trust-m/wiki/Data-format-examples#RSA-Private-Key
        key = (c_ubyte * (100 + 4))()
    else:
        key = byref(c_ushort(key_object.id))
    c_plen = c_ushort(len(pkey))

    ret = api.exp_optiga_crypt_ecc_generate_keypair(c_keytype, c_keyusage, int(export), key, pkey, byref(c_plen))

    if export:
        priv_key = (c_ubyte * (100 + 4))()
        memmove(priv_key, key, 100 + 4)
        pub_key = (c_ubyte * c_plen.value)()
        memmove(pub_key, pkey, c_plen.value)
    else:
        pub_key = (c_ubyte * c_plen.value)()
        memmove(pub_key, pkey, c_plen.value)

    if ret == 0:
        _pkey = rsa_header + bytes(pub_key)
        _key = None
        key_object.key_size = key_size
        if export:
            _key = bytes(priv_key)

        return _pkey, _key

    raise IOError('Function can\'t be executed. Error {0}'.format(hex(ret)))


def generate_pair(key_object, curve=None, key_usage=None, key_size=1024, export=False):
    """
    This function generates a ECC/RSA keypair

    :param key_object:
        Key Object on the OPTIGA Chip, which should be used as a source of the private key storage. Can be
        :class:`~optigatrust.objects.ECCKey` or :class:`~optigatrust.objects.RSAKey`

    :param curve:
        Curve name in string, only EC relevant, should be one of supported by the chip curves. For instance m3 has
        the widest range of supported algorithms: secp256r1, secp384r1, secp521r1, brainpoolp256r1,
        brainpoolp384r1, brainpoolp512r1

    :param key_usage:
        Key usage defined per string. Can be selected as following:
        ['key_agreement', 'authentication', 'encryption', 'signature']

    :param key_size:
        Key size is only RSA relevant, possible values are 1024 and 2048

    :param export:
        Bool type indicates whether the private key should be exported

    :raises:
        - TypeError - when any of the parameters are of the wrong type
        - OSError - when an error is returned by the core initialisation library

    :returns:
        A tuple of keys (public_key, private_key) if export isnt requested, the private part is None
        Example (EC) ::

            public_key= '3059301306072a8648ce3d020106082a8648ce...67477a4deb6ab7d1159ddc0bfe7341e40e9'
            private_key= '308187020100301306072a8648ce3d020106082a86....1159ddc0bfe7341e40e9'

    """
    if isinstance(key_object, objects.ECCKey):
        return _generate_ecc_pair(key_object=key_object, curve=curve, key_usage=key_usage, export=export)

    if isinstance(key_object, objects.RSAKey):
        return _generate_rsa_pair(key_object=key_object, key_size=key_size, key_usage=key_usage, export=export)

    raise ValueError(
        'key_object type isn\'t supported'
    )


def ecdsa_sign(key_object, data):
    """
    This function signs given data based on the provided EccKey object.
    Hash algorithm is selected based on the size of the key

    :param key_object:
        Key Object on the OPTIGA Chip, which should be used as a source of the private key storage :class:`~optigatrust.objects.ECCKey`

    :param data:
        Data to sign, the data will be hashed based on the used curve.
        If secp256r1 then sha256, secp384r1 sha384 etc.

    :raises:
        - TypeError - when any of the parameters are of the wrong type
        - OSError - when an error is returned by the core initialisation library

    :returns:
        EcdsaSignature object or None
    """
    if not isinstance(key_object, objects.ECCKey):
        raise TypeError(
            'key_object is not supported. You provided {0}, expected {1}'.format(type(key_object), objects.ECCKey)
        )
    api = optiga.Chip().api

    if not isinstance(data, bytes) and not isinstance(data, bytearray):
        if isinstance(data, str):
            _d = bytes(data.encode())
            warnings.warn("data will be converted to bytes type before signing")
        else:
            raise TypeError('Data to sign should be either bytes or str type, you gave {0}'.format(type(data)))
    else:
        _d = data

    api.exp_optiga_crypt_ecdsa_sign.argtypes = POINTER(c_ubyte), c_ubyte, c_ushort, POINTER(c_ubyte), POINTER(c_ubyte)
    api.exp_optiga_crypt_ecdsa_sign.restype = c_int
    _map = {
        'secp256r1': [hashlib.sha256, 32, 'sha256'],
        'secp384r1': [hashlib.sha384, 48, 'sha384'],
        'secp521r1': [hashlib.sha512, 64, 'sha512'],
        'brainpoolp256r1': [hashlib.sha256, 32, 'sha256'],
        'brainpoolp384r1': [hashlib.sha384, 48, 'sha384'],
        'brainpoolp512r1': [hashlib.sha512, 64, 'sha512']
    }
    # The curve should be one of supported, so no need for extra check
    param = _map[key_object.curve]
    # This lines are evaluates as following; i.e.
    # digest = (c_ubyte * 32)(*hashlib.sha256(_d).digest())
    # s = (c_ubyte * ((32*2 + 2) + 6))()
    # hash_algorithm = 'sha256'
    digest = (c_ubyte * param[1])(*param[0](_d).digest())
    # We reserve two extra bytes for nistp512r1 curve, shich has signature r/s values longer than a hash size
    sign = (c_ubyte * ((param[1] * 2 + 2) + 6))()
    hash_algorithm = param[2]

    c_slen = c_ubyte(len(sign))

    ret = api.exp_optiga_crypt_ecdsa_sign(digest, len(digest), key_object.id, sign, byref(c_slen))

    if ret == 0:
        signature = (c_ubyte * (c_slen.value + 2))()
        signature[0] = 0x30
        signature[1] = c_slen.value
        memmove(addressof(signature) + 2, sign, c_slen.value)

        return ECDSASignature(hash_algorithm, key_object.id, bytes(signature))

    raise IOError('Function can\'t be executed. Error {0}'.format(hex(ret)))


def ecdh(key_object, external_pkey, export=False):
    """
    This function derives a shared secret using Diffie-Hellman  Key-Exchange. This function assumes the instance
    of the key from which this method will be called represents the private key on the system used for ECDH

    :param key_object:
        Key Object on the OPTIGA Chip, which should be used as a source of the private key storage
        :class:`~optigatrust.objects.ECCKey`

    :param external_pkey:
        a bytearray with a public key You can submit public keys with parameters as per openssl output in DER format
        ::

            from asn1crypto import pem
            # Option 1
            pem_string = '-----BEGIN PUBLIC KEY-----\\n' + \\
                         'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEhqPByq/2I5Xv1jqSZbBzS8fptkdP\\n' + \\
                         'fArs2+l6SZ8IfOIukkf/wHiww0FV+jxehrVyzW+cy9+KftBobalw3iXN2A==\\n' + \\
                         '-----END PUBLIC KEY-----'
            if pem.detect(pem_string):
                type_name, headers, der_bytes = pem.unarmor(pem_string)

            # Option 2
            hex_string ='3059301306072a8648ce3d020106082a' + \\
                        '8648ce3d0301070342000486a3c1caaf' + \\
                        'f62395efd63a9265b0734bc7e9b6474f' + \\
                        '7c0aecdbe97a499f087ce22e9247ffc0' + \\
                        '78b0c34155fa3c5e86b572cd6f9ccbdf' + \\
                        '8a7ed0686da970de25cdd8'
            der_bytes = bytes().from_hex(hex_string)

    :param export:
        defines whether the resulting secret should be exported or not

    :raises:
        - TypeError - when any of the parameters are of the wrong type
        - OSError - when an error is returned by the core initialisation library

    :returns:
        in case `export` set to True returns a shared secret,
        otherwise returns :class:`~optigatrust.objects.AcquiredSession()`
    """
    if not isinstance(key_object, objects.ECCKey):
        raise TypeError(
            'key_object is not supported. You provided {0}, expected {1}'.format(type(key_object), objects.ECCKey)
        )
    if not isinstance(external_pkey, bytes) and not isinstance(external_pkey, bytearray):
        raise TypeError(
            'Public Key should be either bytes or '
            'bytearray type, you gave {0}'.format(type(external_pkey))
        )
    api = optiga.Chip().api
    # OPTIGA doesn't understand the asn.1 encoded parameters field
    external_pkey = _pkcs_to_native(pkey=external_pkey, algorithm=key_object.curve)
    # Extract the curve from the object metadata
    try:
        curve = key_object.meta['algorithm']
    except KeyError as no_meta_found:
        raise ValueError('Given object does\'t have a key populated.') from no_meta_found

    api.exp_optiga_crypt_ecdh.argtypes = c_ushort, POINTER(PublicKeyFromHost), c_ubyte, POINTER(c_ubyte)
    api.exp_optiga_crypt_ecdsa_sign.restype = c_int

    # pylint: disable=attribute-defined-outside-init
    pkey = PublicKeyFromHost()
    pkey.public_key = (c_ubyte * len(external_pkey))()
    memmove(pkey.public_key, external_pkey, len(external_pkey))
    pkey.length = len(external_pkey)
    pkey.key_type = _str2curve(curve, return_value=True)

    if export:
        # Pubkey comprises 4 bytes of asn.1 tags and two coordinates, each of key size
        shared_secret = (c_ubyte * ((len(external_pkey) - 4) >> 1))()
    else:
        shared_secret = None

    ret = api.exp_optiga_crypt_ecdh(key_object.id, byref(pkey), int(export), shared_secret)

    if ret == 0:
        if export:
            return bytes(shared_secret)
        return objects.AcquiredSession()

    raise IOError('Function can\'t be executed. Error {0}'.format(hex(ret)))


def pkcs1v15_sign(key_object, data, hash_algorithm='sha256'):
    """
    This function signs given data based on the provided RsaKey object

    :param key_object:
        Key Object on the OPTIGA Chip, which should be used as a source of the private key storage.
        Should be of type :class:`~optigatrust.objects.RSAKey`

    :param data:
        Data to sign

    :param hash_algorithm:
        Hash algorithm which should be used to sign data. SHA256 by default

    :raises:
        - TypeError - when any of the parameters are of the wrong type
        - OSError - when an error is returned by the core initialisation library

    :returns:
        :class:`~optigatrust.objects.PKCS1v15Signature` object or None
    """
    api = optiga.Chip().api

    if not isinstance(key_object, objects.RSAKey):
        raise TypeError(
            'key_object is not supported. You provided {0}, expected {1}'.format(type(key_object), objects.RSAKey)
        )

    if not isinstance(data, bytes) and not isinstance(data, bytearray):
        if isinstance(data, str):
            _d = bytes(data.encode())
            warnings.warn("data will be converted to bytes type before signing")
        else:
            raise TypeError('Data to sign should be either bytes or str type, you gave {0}'.format(type(data)))
    else:
        _d = data

    api.exp_optiga_crypt_rsa_sign.restype = c_int

    if hash_algorithm == 'sha256':
        digest = (c_ubyte * 32)(*hashlib.sha256(_d).digest())
        sign = (c_ubyte * 320)()
        # Signature schemes RSA SSA PKCS1-v1.5 with SHA256 digest
        sign_scheme = 0x01
    elif hash_algorithm == 'sha384':
        digest = (c_ubyte * 48)(*hashlib.sha384(_d).digest())
        sign = (c_ubyte * 320)()
        # Signature schemes RSA SSA PKCS1-v1.5 with SHA384 digest
        sign_scheme = 0x02
    else:
        raise ValueError('This key isze is not supported, you typed {0} supported are [\'sha256\', \'sha384\']'
                         .format(hash_algorithm))
    c_slen = c_uint(len(sign))

    ret = api.exp_optiga_crypt_rsa_sign(sign_scheme, digest, len(digest), key_object.id, sign, byref(c_slen), 0)

    if ret == 0:
        signature = (c_ubyte * c_slen.value)()
        memmove(addressof(signature), sign, c_slen.value)
        return PKCS1v15Signature(hash_algorithm, key_object.id, bytes(signature))

    raise IOError('Function can\'t be executed. Error {0}'.format(hex(ret)))


def pkcs1v15_encrypt(data, pkey, exp_size='1024'):
    """
    This function encrypts given data with either provided public key, or by extracting the key from the provisioned
    certificate. The certificate should be DER encoded and stored on the chip. The corresponding data object should
    start with 0x30. The keyUsage should be either keyEncipherment, or dataEncipherment

    :param data:
        Data in bytes, str or bytearray to sign

    :param pkey:
        Public key in bytes or bytearray from the user.
        Alternatively you can provide an integer pointing to the certificate id stored on the OPTIGA.
        The device will parse stored certificate and extract the public key from there.

    :param exp_size:
        Exponent size should be either '1024' or '2048'

    :raises:
        - TypeError - when any of the parameters are of the wrong type
        - ValueError - when any of the given parameters don't have an expected value
        - OSError - when an error is returned by the core initialisation library

    :returns:
        bytes or None
    """
    api = optiga.Chip().api

    if not isinstance(pkey, (int, bytes, bytearray)):
        raise TypeError(
            'pkey is not supported. You provided {0}, expected {1}, {2}, or {3}'.
                format(type(pkey), int, bytes, bytearray)
        )

    if not isinstance(data, (bytes, bytearray)):
        if isinstance(data, str):
            _d = bytes(data.encode())
            warnings.warn("data will be converted to bytes type before signing")
        else:
            raise TypeError('Data to encrypt should be either bytes, bytearray or str type, '
                            'you provided {0}'.format(type(data)))
    else:
        _d = data

    if exp_size not in {'1024', '2048'}:
        raise ValueError('This exponent size is not supported, you typed {0} supported are [\'1024\', \'2048\']'
                         .format(exp_size))

    api.optiga_crypt_rsa_encrypt_message.restype = c_int

    encrypt_scheme = 0x11

    data_to_encrypt = (c_ubyte * len(_d))(*_d)

    if isinstance(pkey, int):
        _pkey = c_int(pkey)
        _type = 0x00
    else:
        if pkey[0] != 0x03:
            raise ValueError(
                'See https://github.com/Infineon/optiga-trust-m/wiki/Data-format-examples#RSA-Public-Key.\n'
                'Your key has unsupported format: \n{0}'.format(''.join('{:02x} '.format(x) for x in pkey))
            )
        # pylint: disable=attribute-defined-outside-init
        _pkey = PublicKeyFromHost()
        _pkey.public_key = (c_ubyte * len(pkey))()
        memmove(_pkey.public_key, pkey, len(pkey))
        _pkey.length = len(pkey)
        if exp_size == '1024':
            _pkey.key_type = 0x41
        elif exp_size == '2048':
            _pkey.key_type = 0x42
        else:
            _pkey.key_type = 0x00
        _type = 0x01

    ctext = (c_ubyte * 500)()
    c_ctlen = c_uint(500)

    ret = api.exp_optiga_crypt_rsa_encrypt_message(encrypt_scheme, data_to_encrypt, len(data_to_encrypt),
                                                   None, c_ushort(0),
                                                   _type, byref(_pkey),
                                                   ctext, byref(c_ctlen))

    if ret == 0:
        cipher_text = (c_ubyte * c_ctlen.value)()
        memmove(addressof(cipher_text), ctext, c_ctlen.value)
        return bytes(cipher_text)

    raise IOError('Function can\'t be executed. Error {0}'.format(hex(ret)))


def pkcs1v15_decrypt(ciphertext, key_id):
    """
    This function encrypts given data with either provided public key, or by extracting the key from the provisioned
    certificate. The certificate should be DER encoded and stored on the chip. The corresponding data object should
    start with 0x30. The keyUsage should be either keyEncipherment, or dataEncipherment

    :param ciphertext:
        Encrypted message in bytes or bytearray

    :param key_id:
        Private key stored on the OPTIGA device, should be integer. The private key will be used
        to decrypt given encrypted data.

    :raises:
        - TypeError - when any of the parameters are of the wrong type
        - ValueError - when any of the given parameters don't have an expected value
        - OSError - when an error is returned by the core initialisation library

    :returns:
        bytes or None
    """
    api = optiga.Chip().api

    if not isinstance(ciphertext, (bytes, bytearray)):
        raise TypeError('Data to decrypt should be either bytes or bytearray type, '
                        'you provided {0}'.format(type(ciphertext)))
    else:
        ct = ciphertext

    if not isinstance(key_id, int):
        raise TypeError(
            'key is not supported. You provided {0}, expected {1}'.
                format(type(key_id), int)
        )

    encrypt_scheme = 0x11

    data_to_decrypt = (c_ubyte * len(ct))(*ct)

    plaintext = (c_ubyte * 500)()
    c_ptlen   = c_uint(500)

    ret = api.exp_optiga_crypt_rsa_decrypt_and_export(encrypt_scheme, data_to_decrypt, len(data_to_decrypt),
                                                      None, c_ushort(0),
                                                      key_id,
                                                      plaintext, byref(c_ptlen))

    if ret == 0:
        cipher_text = (c_ubyte * c_ptlen.value)()
        memmove(addressof(cipher_text), plaintext, c_ptlen.value)
        return bytes(cipher_text)

    raise IOError('Function can\'t be executed. Error {0}'.format(hex(ret)))


def hmac(key_object, data, hash_algorithm='sha256'):
    """
    This function calculates a HMAC over a given data using the secret stored on OPTIGA

    .. note:: Only OPTIGA™ Trust M3 relevant

    :param key_object:
        Key Object on the OPTIGA Chip, which should be used as a source of the private key storage.
        Can be one of the following classes
        :class:`~optigatrust.objects.AppData`, :class:`~optigatrust.objects.Session`,
        or :class:`~optigatrust.objects.AcquiredSession`

    :param data:
        A byte string data

    :param hash_algorithm:
        Hash algorithm which should be used to sign data. 'sha256' by default

    :raises:
        - TypeError - when any of the parameters are of the wrong type
        - ValueError - when any of the parameters not expected
        - OSError - when an error is returned by the core initialisation library

    :returns:
        byte string with the resulating MAC
    """
    api = optiga.Chip().api
    if not isinstance(key_object, (objects.AppData, objects.Session, objects.AcquiredSession)):
        raise TypeError(
            'key_object should be either {0}, {1}, or {2} types'.format(
                objects.AppData, objects.Session, objects.AcquiredSession
            )
        )
    if isinstance(key_object, objects.AppData):
        try:
            if key_object.meta['type'] != 'pre_sh_secret':
                raise ValueError(
                    'Selected object doesn\'t have a proper setup.'
                    'Should have PRESHSEC type, you have {0}'.format(key_object.meta['type'])
                )
        except KeyError as no_such_meta:
            raise ValueError(
                'Selected object doesn\'t have a proper setup.'
                'Should have PRESHSEC type'
            ) from no_such_meta
    _hash_map = {
        'sha256': (0x20, 32),
        'sha384': (0x21, 48),
        'sha512': (0x22, 64)
    }
    if hash_algorithm not in _hash_map:
        raise ValueError(
            'Hash algorithm should be one of the following {}'.format(_hash_map.keys())
        )
    if not isinstance(data, (bytearray, bytes)):
        raise TypeError(
            'Data should be byte string, {0} provided.'.format(type(data))
        )
    _data = (c_ubyte * len(data))(*data)
    mac = (c_ubyte * _hash_map[hash_algorithm][1])()
    mac_len = c_uint(_hash_map[hash_algorithm][1])

    ret = api.exp_optiga_crypt_hmac(_hash_map[hash_algorithm][0], key_object.id, _data, len(_data), mac, byref(mac_len))

    if ret == 0:
        return bytes(mac)

    raise IOError('Function can\'t be executed. Error {0}'.format(hex(ret)))


# pylint: disable=too-many-arguments disable=too-many-branches
def tls_prf(obj, key_length, seed, label=None, hash_algorithm='sha256', export=False):  # noqa: C901
    """
    This function derives a key (TLS PRF) using the secret stored on OPTIGA

    .. note:: SHA384 and SH512 are only OPTIGA™ Trust M3 relevant

    :param obj:
        Key Object on the OPTIGA Chip, which should be used as a source of the private key storage.
        Can be one of the following classes
        :class:`~optigatrust.objects.AppData`, :class:`~optigatrust.objects.AcquiredSession`

    :param key_length:
        Size of the requested key.
        Minimum Length = 16 byte; maximum length = 66 bytes (in case of OPTIGA™ Trust M V1, = 48 bytes) in case of
        session reference; maximum length = 256 byte in case of returned secret

    :param seed:
        Optional seed, should be bytestring

    :param label:
        Optional label, should be bytestring

    :param hash_algorithm:
        Hash algorithm which should be used to sign data. 'sha256' by default

    :param export:
        set it to True, if you would like to export the resulting. In other case the key will e stored in the
        :class:`~optigatrust.objects.AcquiredSession`

    :raises:
        - TypeError - when any of the parameters are of the wrong type
        - ValueError - when any of the parameters not expected
        - OSError - when an error is returned by the core initialisation library

    :returns:
        byte string with the key if requested, otherwise :class:`~optigatrust.objects.AcquiredSession`
    """
    api = optiga.Chip().api
    if not isinstance(obj, (objects.AppData, objects.AcquiredSession)):
        raise TypeError(
            'key_object should be either {0}, or {1} types'.format(objects.AppData, objects.AcquiredSession)
        )
    if isinstance(obj, objects.AppData):
        try:
            if obj.meta['type'] != 'pre_sh_secret':
                raise ValueError(
                    'Selected object doesn\'t have a proper setup.'
                    'Should have PRESHSEC type, you have {0}'.format(obj.meta['type'])
                )
        except KeyError as no_meta_found:
            raise ValueError(
                'Selected object doesn\'t have a proper setup.'
                'Should have PRESHSEC type'
            ) from no_meta_found
    _hash_map = {
        'sha256': 0x01,
        'sha384': 0x02,
        'sha512': 0x03
    }
    if hash_algorithm not in _hash_map:
        raise ValueError(
            'Hash algorithm should be one of the following {}'.format(_hash_map.keys())
        )

    if label is None:
        label_len = c_ushort(0)
    else:
        label_len = c_ushort(len(label))

    if seed is None:
        seed_len = c_ushort(0)
    else:
        seed_len = c_ushort(len(seed))

    if export:
        derived_key = (c_ubyte * key_length)()
    else:
        derived_key = None

    ret = api.exp_optiga_crypt_tls_prf(_hash_map[hash_algorithm], obj.id, label, label_len,
                                       seed, seed_len, key_length, int(export), derived_key)

    if ret == 0:
        if export:
            return bytes(derived_key)

        return objects.AcquiredSession()

    raise IOError('Function can\'t be executed. Error {0}'.format(hex(ret)))


# pylint: disable=too-many-arguments disable=too-many-branches
def hkdf(key_object, key_length, salt=None, info=None, hash_algorithm='sha256', export=False):  # noqa: C901
    """
    This function derives a key (HKDF) using the secret stored on OPTIGA

    .. note:: Only OPTIGA™ Trust M3 relevant

    :param key_object:
        Key Object on the OPTIGA Chip, which should be used as a source of the private key storage.
        Can be one of the following classes
        :class:`~optigatrust.objects.AppData`, :class:`~optigatrust.objects.AcquiredSession`

    :param key_length:
        Size of the requested key.
        Minimum Length = 16 byte; maximum length = 66 bytes (in case of OPTIGA™ Trust M V1, = 48 bytes) in case of
        session reference; maximum length = 256 byte in case of returned secret

    :param salt:
        Optional salt, should be bytestring

    :param info:
        Optional info, should be bytestring

    :param hash_algorithm:
        Hash algorithm which should be used to sign data. 'sha256' by default

    :param export:
        set it to True, if you would like to export the resulting. In other case the key will e stored in the
        :class:`~optigatrust.objects.AcquiredSession`

    :raises:
        - TypeError - when any of the parameters are of the wrong type
        - ValueError - when any of the parameters not expected
        - OSError - when an error is returned by the core initialisation library

    :returns:
        byte string with the key if requested, otherwise :class:`~optigatrust.objects.AcquiredSession`
    """
    api = optiga.Chip().api
    if not isinstance(key_object, (objects.AppData, objects.AcquiredSession)):
        raise TypeError(
            'key_object should be either {0},  or {1} types'.format(objects.AppData, objects.AcquiredSession)
        )
    if isinstance(key_object, objects.AppData):
        try:
            if key_object.meta['type'] != 'pre_sh_secret':
                raise ValueError(
                    'Selected object doesn\'t have a proper setup.'
                    'Should have PRESHSEC type, you have {0}'.format(key_object.meta['type'])
                )
        except KeyError as no_meta_found:
            raise ValueError(
                'Selected object doesn\'t have a proper setup.'
                'Should have PRESHSEC type'
            ) from no_meta_found
    _hash_map = {
        'sha256': 0x08,
        'sha384': 0x09,
        'sha512': 0x0a
    }
    if hash_algorithm not in _hash_map:
        raise ValueError(
            'Hash algorithm should be one of the following {}'.format(_hash_map.keys())
        )

    if salt is None:
        salt_len = c_ushort(0)
    else:
        salt_len = c_ushort(len(salt))
    if info is None:
        info_len = c_ushort(0)
    else:
        info_len = c_ushort(len(info))

    if export:
        derived_key = (c_ubyte * key_length)()
    else:
        derived_key = None

    ret = api.exp_optiga_crypt_hkdf(_hash_map[hash_algorithm], key_object.id, salt, byref(salt_len),
                                    info, byref(info_len), key_length, int(export), derived_key)

    if ret == 0:
        if export:
            return bytes(derived_key)

        return objects.AcquiredSession()

    raise IOError('Function can\'t be executed. Error {0}'.format(hex(ret)))

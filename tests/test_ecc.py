import pytest
from optigatrust.crypto import ECCKey
from oscrypto import asymmetric as oscrypto_ecc

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_der_public_key


import logging

LOGGER = logging.getLogger(__name__)


def test_keypair_default():
    LOGGER.info('Generate a keypair using default parameters')
    k = ECCKey(0xe0f1).generate_pair()
    assert isinstance(k.pkey, bytes)
    assert len(k.pkey) > 0
    assert len(k.pkey) == 68
    assert isinstance(k.curve, str)


@pytest.mark.parametrize("oid, curve, pub_key_size", [
    (0xe0f1, 'secp256r1', 68), (0xe0f1, 'secp384r1', 100), (0xe0f1, 'secp521r1', 137),
    (0xe0f1, 'brainpoolp256r1', 68), (0xe0f1, 'brainpoolp384r1', 100), (0xe0f1, 'brainpoolp512r1', 133),
    (0xe0f2, 'secp256r1', 68), (0xe0f2, 'secp384r1', 100), (0xe0f2, 'secp521r1', 137),
    (0xe0f2, 'brainpoolp256r1', 68), (0xe0f2, 'brainpoolp384r1', 100), (0xe0f2, 'brainpoolp512r1', 133),
    (0xe0f3, 'secp256r1', 68), (0xe0f3, 'secp384r1', 100), (0xe0f3, 'secp521r1', 137),
    (0xe0f3, 'brainpoolp256r1', 68), (0xe0f3, 'brainpoolp384r1', 100), (0xe0f3, 'brainpoolp512r1', 133),
    (0xE100, 'secp256r1', 68), (0xE100, 'secp384r1', 100), (0xE100, 'secp521r1', 137),
    (0xE100, 'brainpoolp256r1', 68), (0xE100, 'brainpoolp384r1', 100), (0xE100, 'brainpoolp512r1', 133),
    (0xE101, 'secp256r1', 68), (0xE101, 'secp384r1', 100), (0xE101, 'secp521r1', 137),
    (0xE101, 'brainpoolp256r1', 68), (0xE101, 'brainpoolp384r1', 100), (0xE101, 'brainpoolp512r1', 133),
    (0xE102, 'secp256r1', 68), (0xE102, 'secp384r1', 100), (0xE102, 'secp521r1', 137),
    (0xE102, 'brainpoolp256r1', 68), (0xE102, 'brainpoolp384r1', 100), (0xE102, 'brainpoolp512r1', 133),
    (0xE103, 'secp256r1', 68), (0xE103, 'secp384r1', 100), (0xE103, 'secp521r1', 137),
    (0xE103, 'brainpoolp256r1', 68), (0xE103, 'brainpoolp384r1', 100), (0xE103, 'brainpoolp512r1', 133)
])
def test_keypair_x_y(oid, curve, pub_key_size):
    LOGGER.info('Generate a keypair on {0} slot using {1} curve'.format(hex(oid), curve))
    k = ECCKey(oid).generate_pair(curve=curve)
    assert isinstance(k.pkey, bytes)
    assert len(k.pkey) > 0
    assert len(k.pkey) == pub_key_size
    assert k.id == oid
    assert k.curve == curve


def test_keypair_faulty():
    LOGGER.info('Try to use faulty curves and keyid')
    with pytest.raises(ValueError):
        ECCKey(0xe0f1).generate_pair(curve='secp384')

    with pytest.raises(ValueError):
        ECCKey(0xe0fc).generate_pair(curve='secp384r1')

def test_ecdh_internal():
    key_handle = ECCKey(0xe0f1)
    int_key = key_handle.generate_pair('secp256r1')
    ext_pkey, _ = oscrypto_ecc.generate_pair(algorithm='ec', curve='secp256r1')
    key_handle.ecdh(ext_pkey.asn1.dump())

def test_ecdh_external():
    key_handle = ECCKey(0xe0f1)
    int_key = key_handle.generate_pair('secp256r1')
    ext_pkey, _ = oscrypto_ecc.generate_pair(algorithm='ec', curve='secp256r1')
    shared_secret = key_handle.ecdh(ext_pkey.asn1.dump(), export=True)

def test_ecdh_verify():
    key_handle = ECCKey(0xe0f1)
    int_key = key_handle.generate_pair('secp256r1')
    header = '3059301306072a8648ce3d020106082a8648ce3d030107'
    int_key_hex = header + int_key.pkey.hex()
    int_key_bytes = bytes().fromhex(int_key_hex)
    private_key = ec.generate_private_key(ec.SECP256R1())
    peer_publec_key = private_key.public_key()
    shared_secret = key_handle.ecdh(peer_publec_key.public_bytes(encoding=serialization.Encoding.DER,
                                                                 format=serialization.PublicFormat.SubjectPublicKeyInfo),
                                    export=True)
    key = load_der_public_key(int_key_bytes, default_backend())
    shared_secret_to_check = private_key.exchange(ec.ECDH(), key)

    assert shared_secret == shared_secret_to_check



def test_ecdh_export():

import pytest
import os
import sys

if sys.platform == 'win32':
    from oscrypto import use_openssl
    libcrypto_path = os.path.abspath("C:\\Program Files (x86)\\OpenSSL-Win32\\libcrypto-1_1.dll")
    libssl_path = os.path.abspath("C:\\Program Files (x86)\\OpenSSL-Win32\\libssl-1_1.dll")
    use_openssl(libcrypto_path, libssl_path)

from oscrypto.asymmetric import ecdsa_verify, load_public_key
from oscrypto.errors import SignatureError
from asn1crypto import keys, core

from optigatrust import objects
from optigatrust import crypto

tbs_str = b'Test String to Sign'
tbs_str_fail = b'FAILED Test String to Sign'


@pytest.mark.parametrize("oid, curve, max_sign_size, hashname", [
    (0xe0f1, 'secp256r1', 72, 'sha256'), (0xe0f1, 'secp384r1', 104, 'sha384'), (0xe0f1, 'secp521r1', 141, 'sha512'),
    (0xe0f1, 'brainpoolp256r1', 72, 'sha256'), (0xe0f1, 'brainpoolp384r1', 104, 'sha384'),
    (0xe0f1, 'brainpoolp512r1', 137, 'sha512'),

    (0xe0f2, 'secp256r1', 72, 'sha256'), (0xe0f2, 'secp384r1', 104, 'sha384'), (0xe0f2, 'secp521r1', 141, 'sha512'),
    (0xe0f2, 'brainpoolp256r1', 72, 'sha256'), (0xe0f2, 'brainpoolp384r1', 104, 'sha384'),
    (0xe0f2, 'brainpoolp512r1', 137, 'sha512'),

    (0xe0f3, 'secp256r1', 72, 'sha256'), (0xe0f3, 'secp384r1', 104, 'sha384'), (0xe0f3, 'secp521r1', 141, 'sha512'),
    (0xe0f3, 'brainpoolp256r1', 72, 'sha256'), (0xe0f3, 'brainpoolp384r1', 104, 'sha384'),
    (0xe0f3, 'brainpoolp512r1', 137, 'sha512'),

    (0xE100, 'secp256r1', 72, 'sha256'), (0xE100, 'secp384r1', 104, 'sha384'), (0xE100, 'secp521r1', 141, 'sha512'),
    (0xE100, 'brainpoolp256r1', 72, 'sha256'), (0xE100, 'brainpoolp384r1', 104, 'sha384'),
    (0xE100, 'brainpoolp512r1', 137, 'sha512'),

    (0xE101, 'secp256r1', 72, 'sha256'), (0xE101, 'secp384r1', 104, 'sha384'), (0xE101, 'secp521r1', 141, 'sha512'),
    (0xE101, 'brainpoolp256r1', 72, 'sha256'), (0xE101, 'brainpoolp384r1', 104, 'sha384'),
    (0xE101, 'brainpoolp512r1', 137, 'sha512'),

    (0xE102, 'secp256r1', 72, 'sha256'), (0xE102, 'secp384r1', 104, 'sha384'), (0xE102, 'secp521r1', 141, 'sha512'),
    (0xE102, 'brainpoolp256r1', 72, 'sha256'), (0xE102, 'brainpoolp384r1', 104, 'sha384'),
    (0xE102, 'brainpoolp512r1', 137, 'sha512'),

    (0xE103, 'secp256r1', 72, 'sha256'), (0xE103, 'secp384r1', 104, 'sha384'), (0xE103, 'secp521r1', 141, 'sha512'),
    (0xE103, 'brainpoolp256r1', 72, 'sha256'), (0xE103, 'brainpoolp384r1', 104, 'sha384'),
    (0xE103, 'brainpoolp512r1', 137, 'sha512')
])
def test_ecdsa(oid, curve, max_sign_size, hashname):
    key_object = objects.ECCKey(oid)
    _, _ = crypto.generate_pair(key_object, curve=curve)
    s = crypto.ecdsa_sign(key_object, tbs_str)
    assert isinstance(s.signature, bytes)
    assert len(s.signature) > 0
    assert len(s.signature) <= max_sign_size
    assert s.hash_alg == hashname
    assert s.algorithm == hashname + '_ecdsa'


@pytest.mark.parametrize("curve, hashname", [
    ('secp256r1', 'sha256'), ('brainpoolp256r1', 'sha256'),
    ('secp384r1', 'sha384'), ('brainpoolp384r1', 'sha384'),
    ('secp521r1', 'sha512'), ('brainpoolp512r1', 'sha512'),
])
def test_ecdsa_signverify(curve, hashname):
    key_object = objects.ECCKey(0xE100)
    pkey, _ = crypto.generate_pair(key_object, curve=curve)
    key_object_fail = objects.ECCKey(0xE101)
    pkey_fail, _ = crypto.generate_pair(key_object_fail, curve=curve)
    ha = hashname
    s = crypto.ecdsa_sign(key_object, tbs_str)
    print('[{}]'.format(', '.join(hex(x) for x in list(s.signature))))

    # Preparing a PublicKeyInfo
    pubkey_info = keys.PublicKeyInfo.load(pkey)

    # Load a public key into the oscrypto engine to using it in the verify function
    public = load_public_key(pubkey_info)

    ecdsa_verify(public, s.signature, tbs_str, ha)

    # Assert wrong text
    with pytest.raises(SignatureError):
        ecdsa_verify(public, s.signature, tbs_str_fail, ha)

    # Assert wrong key
    with pytest.raises(SignatureError):
        # Preparing a PublicKeyInfo
        pubkey_info = keys.PublicKeyInfo.load(pkey_fail)

        # Load a public key into the oscrypto engine to using it in the verify function
        public = load_public_key(pubkey_info)
        ecdsa_verify(public, s.signature, tbs_str, ha)


def test_ecdsa_nonkey():
    ecc_key = bytes(35)
    with pytest.raises(TypeError):
        crypto.ecdsa_sign(ecc_key, tbs_str)


def test_ecdsa_nonkey_2():
    with pytest.raises(TypeError):
        crypto.ecdsa_sign(int(19273917398739829))

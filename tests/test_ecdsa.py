# SPDX-FileCopyrightText: 2021-2024 Infineon Technologies AG
# SPDX-License-Identifier: MIT

import pytest

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

from optigatrust import objects, crypto, util

tbs_str = b"Test String to Sign"
tbs_str_fail = b"FAILED Test String to Sign"


@pytest.mark.parametrize(
    "oid, curve, max_sign_size, hash_name",
    [
        (0xE0F1, "secp256r1", 72, "sha256"),
        (0xE0F1, "secp384r1", 104, "sha384"),
        (0xE0F1, "secp521r1", 141, "sha512"),
        (0xE0F1, "brainpoolp256r1", 72, "sha256"),
        (0xE0F1, "brainpoolp384r1", 104, "sha384"),
        (0xE0F1, "brainpoolp512r1", 137, "sha512"),
        (0xE0F2, "secp256r1", 72, "sha256"),
        (0xE0F2, "secp384r1", 104, "sha384"),
        (0xE0F2, "secp521r1", 141, "sha512"),
        (0xE0F2, "brainpoolp256r1", 72, "sha256"),
        (0xE0F2, "brainpoolp384r1", 104, "sha384"),
        (0xE0F2, "brainpoolp512r1", 137, "sha512"),
        (0xE0F3, "secp256r1", 72, "sha256"),
        (0xE0F3, "secp384r1", 104, "sha384"),
        (0xE0F3, "secp521r1", 141, "sha512"),
        (0xE0F3, "brainpoolp256r1", 72, "sha256"),
        (0xE0F3, "brainpoolp384r1", 104, "sha384"),
        (0xE0F3, "brainpoolp512r1", 137, "sha512"),
        (0xE100, "secp256r1", 72, "sha256"),
        (0xE100, "secp384r1", 104, "sha384"),
        (0xE100, "secp521r1", 141, "sha512"),
        (0xE100, "brainpoolp256r1", 72, "sha256"),
        (0xE100, "brainpoolp384r1", 104, "sha384"),
        (0xE100, "brainpoolp512r1", 137, "sha512"),
        (0xE101, "secp256r1", 72, "sha256"),
        (0xE101, "secp384r1", 104, "sha384"),
        (0xE101, "secp521r1", 141, "sha512"),
        (0xE101, "brainpoolp256r1", 72, "sha256"),
        (0xE101, "brainpoolp384r1", 104, "sha384"),
        (0xE101, "brainpoolp512r1", 137, "sha512"),
        (0xE102, "secp256r1", 72, "sha256"),
        (0xE102, "secp384r1", 104, "sha384"),
        (0xE102, "secp521r1", 141, "sha512"),
        (0xE102, "brainpoolp256r1", 72, "sha256"),
        (0xE102, "brainpoolp384r1", 104, "sha384"),
        (0xE102, "brainpoolp512r1", 137, "sha512"),
        (0xE103, "secp256r1", 72, "sha256"),
        (0xE103, "secp384r1", 104, "sha384"),
        (0xE103, "secp521r1", 141, "sha512"),
        (0xE103, "brainpoolp256r1", 72, "sha256"),
        (0xE103, "brainpoolp384r1", 104, "sha384"),
        (0xE103, "brainpoolp512r1", 137, "sha512"),
    ],
)
def test_ecdsa(oid, curve, max_sign_size, hash_name):
    key_object = objects.ECCKey(oid)
    _, _ = crypto.generate_pair(key_object, curve=curve)
    s = crypto.ecdsa_sign(key_object, tbs_str)
    assert isinstance(s.signature, bytes)
    assert len(s.signature) > 0
    assert len(s.signature) <= max_sign_size
    assert s.hash_alg == hash_name
    assert s.algorithm == hash_name + "_ecdsa"


@pytest.mark.parametrize(
    "curve, hash_name",
    [
        ("secp256r1", "sha256"),
        ("brainpoolp256r1", "sha256"),
        ("secp384r1", "sha384"),
        ("brainpoolp384r1", "sha384"),
        ("secp521r1", "sha512"),
        ("brainpoolp512r1", "sha512"),
    ],
)
def test_ecdsa_signverify(curve, hash_name):
    ecdsa_signverify_pk_host(curve, hash_name)
    ecdsa_signverify_oid(curve, hash_name)


def ecdsa_signverify_pk_host(curve, hash_name):
    # Generate key pair for curve
    key_object = objects.ECCKey(0xE100)
    public_key, _ = crypto.generate_pair(key_object, curve=curve)

    key_object_fail = objects.ECCKey(0xE101)
    public_key_fail, _ = crypto.generate_pair(key_object_fail, curve=curve)

    # Sign data
    signature = crypto.ecdsa_sign_with_hash(key_object, tbs_str, hash_name).signature

    print("Public key:")
    util.print_binary(public_key)
    print("Signature:")
    util.print_binary(signature)

    # Verify the signature on OPTIGA Trust M using a public key from host
    crypto.ecdsa_verify_data_pk_host(signature, tbs_str, hash_name, public_key, curve)

    # Assert wrong text
    with pytest.raises(OSError):
        crypto.ecdsa_verify_data_pk_host(signature, tbs_str_fail, hash_name, public_key, curve)

    # Assert wrong key
    with pytest.raises(OSError):
        crypto.ecdsa_verify_data_pk_host(signature, tbs_str, hash_name, public_key_fail, curve)

    # Check also with cryptography package

    # Verify the signature with cryptography package
    cryptography_public_key = serialization.load_der_public_key(public_key)
    cryptography_public_key.verify(signature, tbs_str, ec.ECDSA(crypto._hash_map[hash_name][2]))

    # Assert wrong text
    with pytest.raises(InvalidSignature):
        cryptography_public_key.verify(
            signature, tbs_str_fail, ec.ECDSA(crypto._hash_map[hash_name][2])
        )

    # Assert wrong key
    with pytest.raises(InvalidSignature):
        cryptography_public_key = serialization.load_der_public_key(public_key_fail)
        cryptography_public_key.verify(signature, tbs_str, ec.ECDSA(crypto._hash_map[hash_name][2]))


def ecdsa_signverify_oid(curve, hash_name):
    key_oid = 0xE0F2
    key_oid_fail = 0xE0F3
    cert_oid = 0xE0E3

    # Generate key pair for curve
    key_object = objects.ECCKey(key_oid)
    public_key, _ = crypto.generate_pair(key_object, curve=curve)

    key_object_fail = objects.ECCKey(key_oid_fail)
    public_key_fail, _ = crypto.generate_pair(key_object_fail, curve=curve)

    # Sign data
    signature = crypto.ecdsa_sign_with_hash(key_object, tbs_str, hash_name).signature

    print("Public key:")
    util.print_binary(public_key)
    print("Signature:")
    util.print_binary(signature)

    # Generate ephemeral certificates
    cert = util.generate_ephemeral_certificate(public_key)
    cert_der = cert.public_bytes(serialization.Encoding.DER)

    print("Certificate:\n{0}".format(util.binary_to_hex(cert_der)))

    # Write certificate to OPTIGA™ Trust M
    cert_object_new = objects.X509(cert_oid)
    cert_object_new.der = cert_der
    cert_object_new.write(cert_object_new.der)

    # Verify signature via OPTIGA™ Trust M using certificate referenced by OID
    crypto.ecdsa_verify_data_oid(signature, tbs_str, hash_name, cert_oid)

    # Assert wrong text
    with pytest.raises(OSError):
        crypto.ecdsa_verify_data_oid(signature, tbs_str_fail, hash_name, cert_oid)

    # Generate ephemeral certificates
    fail_cert = util.generate_ephemeral_certificate(public_key_fail)
    fail_cert_der = fail_cert.public_bytes(serialization.Encoding.DER)

    print("Certificate:\n{0}".format(util.binary_to_hex(fail_cert_der)))

    # Write certificate to OPTIGA™ Trust M
    cert_object_new = objects.X509(cert_oid)
    cert_object_new.der = fail_cert_der
    cert_object_new.write(cert_object_new.der)

    # Assert wrong key
    with pytest.raises(OSError):
        crypto.ecdsa_verify_data_oid(signature, tbs_str, hash_name, cert_oid)


def test_ecdsa_nonkey():
    ecc_key = bytes(35)
    with pytest.raises(TypeError):
        crypto.ecdsa_sign(ecc_key, tbs_str)


def test_ecdsa_nonkey_2():
    with pytest.raises(TypeError):
        crypto.ecdsa_sign(int(19273917398739829))

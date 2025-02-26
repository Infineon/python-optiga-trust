# SPDX-FileCopyrightText: 2021-2024 Infineon Technologies AG
# SPDX-License-Identifier: MIT

import pytest
import optigatrust.objects as objects
import optigatrust.crypto as optiga_ec

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_der_public_key


def test_ecdh_faulty():
    with pytest.raises(IOError):
        key_object = objects.ECCKey(0xE0F1)
        pkey, _ = optiga_ec.generate_pair(
            key_object, curve="secp384r1", key_usage=["authentication", "signature"]
        )
        # key agreement hasnt been selected, thus an error
        optiga_ec.ecdh(key_object, pkey)


@pytest.mark.parametrize(
    "curve, hazmat_curve",
    [
        ("secp256r1", ec.SECP256R1()),
        ("secp384r1", ec.SECP384R1()),
        ("secp521r1", ec.SECP521R1()),
        ("brainpoolp256r1", ec.BrainpoolP256R1()),
        ("brainpoolp384r1", ec.BrainpoolP384R1()),
        ("brainpoolp512r1", ec.BrainpoolP512R1()),
    ],
)
def test_ecdh_internal(curve, hazmat_curve):
    key_object = objects.ECCKey(0xE0F1)
    _, _ = optiga_ec.generate_pair(key_object, curve)
    private_key = ec.generate_private_key(hazmat_curve, default_backend())
    peer_public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    optiga_ec.ecdh(key_object, peer_public_key)


@pytest.mark.parametrize(
    "curve, hazmat_curve",
    [
        ("secp256r1", ec.SECP256R1()),
        ("secp384r1", ec.SECP384R1()),
        ("secp521r1", ec.SECP521R1()),
        ("brainpoolp256r1", ec.BrainpoolP256R1()),
        ("brainpoolp384r1", ec.BrainpoolP384R1()),
        ("brainpoolp512r1", ec.BrainpoolP512R1()),
    ],
)
def test_ecdh_external(curve, hazmat_curve):
    key_object = objects.ECCKey(0xE0F1)
    _, _ = optiga_ec.generate_pair(key_object, curve)
    private_key = ec.generate_private_key(hazmat_curve, default_backend())
    peer_public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    _ = optiga_ec.ecdh(key_object, peer_public_key, export=True)


def test_ecdh_verify():
    key_object = objects.ECCKey(0xE0F1)
    int_key_bytes, _ = optiga_ec.generate_pair(key_object, "secp256r1")
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    peer_public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    shared_secret = optiga_ec.ecdh(key_object, peer_public_key, export=True)
    key = load_der_public_key(int_key_bytes, default_backend())
    shared_secret_to_check = private_key.exchange(ec.ECDH(), key)

    assert shared_secret == shared_secret_to_check

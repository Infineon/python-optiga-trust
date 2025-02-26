# SPDX-FileCopyrightText: 2021-2024 Infineon Technologies AG
# SPDX-License-Identifier: MIT

import pytest
import optigatrust.objects as objects
import optigatrust.crypto as optiga_ec

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


@pytest.mark.parametrize(
    "hash_alg, hazmat_curve, curve",
    [
        (
            "sha256",
            ec.SECP256R1(),
            "secp256r1",
        ),
        (
            "sha384",
            ec.SECP384R1(),
            "secp384r1",
        ),
        (
            "sha512",
            ec.SECP521R1(),
            "secp521r1",
        ),
        (
            "sha256",
            ec.BrainpoolP256R1(),
            "brainpoolp256r1",
        ),
        (
            "sha384",
            ec.BrainpoolP384R1(),
            "brainpoolp384r1",
        ),
        (
            "sha512",
            ec.BrainpoolP512R1(),
            "brainpoolp512r1",
        ),
    ],
)
def test_hmac(hash_alg, hazmat_curve, curve):
    key = objects.ECCKey(0xE0F1)
    _, _ = optiga_ec.generate_pair(key, curve=curve)
    private_key = ec.generate_private_key(hazmat_curve, default_backend())
    peer_public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    session_object = optiga_ec.ecdh(key, peer_public_key)
    data = "Hello world!"
    mac = optiga_ec.hmac(session_object, str.encode(data), hash_algorithm=hash_alg)
    assert mac is not None

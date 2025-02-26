# SPDX-FileCopyrightText: 2021-2024 Infineon Technologies AG
# SPDX-License-Identifier: MIT

import pytest
import optigatrust.objects as objects
import optigatrust.crypto as optiga_ec

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


def test_keypair_default():
    key_object = objects.ECCKey(0xE0F1)
    pkey, _ = optiga_ec.generate_pair(key_object, curve="secp256r1")
    assert isinstance(pkey, bytes)
    assert len(pkey) > 0
    assert key_object.meta["algorithm"] == "secp256r1"


@pytest.mark.parametrize(
    "oid, curve, pub_key_size",
    [
        (0xE0F1, "secp256r1", 91),
        (0xE0F1, "secp384r1", 120),
        (0xE0F1, "secp521r1", 158),
        (0xE0F1, "brainpoolp256r1", 92),
        (0xE0F1, "brainpoolp384r1", 124),
        (0xE0F1, "brainpoolp512r1", 158),
        (0xE0F2, "secp256r1", 91),
        (0xE0F2, "secp384r1", 120),
        (0xE0F2, "secp521r1", 158),
        (0xE0F2, "brainpoolp256r1", 92),
        (0xE0F2, "brainpoolp384r1", 124),
        (0xE0F2, "brainpoolp512r1", 158),
        (0xE0F3, "secp256r1", 91),
        (0xE0F3, "secp384r1", 120),
        (0xE0F3, "secp521r1", 158),
        (0xE0F3, "brainpoolp256r1", 92),
        (0xE0F3, "brainpoolp384r1", 124),
        (0xE0F3, "brainpoolp512r1", 158),
        (0xE100, "secp256r1", 91),
        (0xE100, "secp384r1", 120),
        (0xE100, "secp521r1", 158),
        (0xE100, "brainpoolp256r1", 92),
        (0xE100, "brainpoolp384r1", 124),
        (0xE100, "brainpoolp512r1", 158),
        (0xE101, "secp256r1", 91),
        (0xE101, "secp384r1", 120),
        (0xE101, "secp521r1", 158),
        (0xE101, "brainpoolp256r1", 92),
        (0xE101, "brainpoolp384r1", 124),
        (0xE101, "brainpoolp512r1", 158),
        (0xE102, "secp256r1", 91),
        (0xE102, "secp384r1", 120),
        (0xE102, "secp521r1", 158),
        (0xE102, "brainpoolp256r1", 92),
        (0xE102, "brainpoolp384r1", 124),
        (0xE102, "brainpoolp512r1", 158),
        (0xE103, "secp256r1", 91),
        (0xE103, "secp384r1", 120),
        (0xE103, "secp521r1", 158),
        (0xE103, "brainpoolp256r1", 92),
        (0xE103, "brainpoolp384r1", 124),
        (0xE103, "brainpoolp512r1", 158),
    ],
)
def test_keypair_x_y(oid, curve, pub_key_size):
    key_object = objects.ECCKey(oid)
    pkey, _ = optiga_ec.generate_pair(key_object, curve=curve)
    pkey, key = optiga_ec.generate_pair(key_object, curve=curve, export=True)
    assert isinstance(pkey, bytes)
    assert isinstance(key, bytes)
    assert len(pkey) > 0
    assert len(key) > 0
    assert len(pkey) == pub_key_size
    assert key_object.id == oid
    assert key_object.curve == curve


@pytest.mark.parametrize(
    "oid, curve",
    [
        (0xE0F1, "secp256r1"),
        (0xE0F1, "secp384r1"),
        (
            0xE0F1,
            "secp521r1",
        ),
        (0xE0F1, "brainpoolp256r1"),
        (0xE0F1, "brainpoolp384r1"),
        (0xE0F1, "brainpoolp512r1"),
        (0xE0F2, "secp256r1"),
        (0xE0F2, "secp384r1"),
        (0xE0F2, "secp521r1"),
        (0xE0F2, "brainpoolp256r1"),
        (0xE0F2, "brainpoolp384r1"),
        (0xE0F2, "brainpoolp512r1"),
        (0xE0F3, "secp256r1"),
        (0xE0F3, "secp384r1"),
        (0xE0F3, "secp521r1"),
        (0xE0F3, "brainpoolp256r1"),
        (0xE0F3, "brainpoolp384r1"),
        (0xE0F3, "brainpoolp512r1"),
        (0xE100, "secp256r1"),
        (0xE100, "secp384r1"),
        (0xE100, "secp521r1"),
        (0xE100, "brainpoolp256r1"),
        (0xE100, "brainpoolp384r1"),
        (0xE100, "brainpoolp512r1"),
        (0xE101, "secp256r1"),
        (0xE101, "secp384r1"),
        (0xE101, "secp521r1"),
        (0xE101, "brainpoolp256r1"),
        (0xE101, "brainpoolp384r1"),
        (0xE101, "brainpoolp512r1"),
        (0xE102, "secp256r1"),
        (0xE102, "secp384r1"),
        (0xE102, "secp521r1"),
        (0xE102, "brainpoolp256r1"),
        (0xE102, "brainpoolp384r1"),
        (0xE102, "brainpoolp512r1"),
        (0xE103, "secp256r1"),
        (0xE103, "secp384r1"),
        (0xE103, "secp521r1"),
        (0xE103, "brainpoolp256r1"),
        (0xE103, "brainpoolp384r1"),
        (0xE103, "brainpoolp512r1"),
    ],
)
def test_keypair_x_y_private_key_import(oid, curve):
    key_object = objects.ECCKey(oid)
    _, key = optiga_ec.generate_pair(key_object, curve=curve, export=True)
    parsed_key = serialization.load_der_private_key(key, password=None, backend=default_backend())
    assert isinstance(parsed_key, ec.EllipticCurvePrivateKey)


@pytest.mark.parametrize(
    "oid, curve",
    [
        (0xE0F1, "secp256r1"),
        (0xE0F1, "secp384r1"),
        (
            0xE0F1,
            "secp521r1",
        ),
        (0xE0F1, "brainpoolp256r1"),
        (0xE0F1, "brainpoolp384r1"),
        (0xE0F1, "brainpoolp512r1"),
        (0xE0F2, "secp256r1"),
        (0xE0F2, "secp384r1"),
        (0xE0F2, "secp521r1"),
        (0xE0F2, "brainpoolp256r1"),
        (0xE0F2, "brainpoolp384r1"),
        (0xE0F2, "brainpoolp512r1"),
        (0xE0F3, "secp256r1"),
        (0xE0F3, "secp384r1"),
        (0xE0F3, "secp521r1"),
        (0xE0F3, "brainpoolp256r1"),
        (0xE0F3, "brainpoolp384r1"),
        (0xE0F3, "brainpoolp512r1"),
        (0xE100, "secp256r1"),
        (0xE100, "secp384r1"),
        (0xE100, "secp521r1"),
        (0xE100, "brainpoolp256r1"),
        (0xE100, "brainpoolp384r1"),
        (0xE100, "brainpoolp512r1"),
        (0xE101, "secp256r1"),
        (0xE101, "secp384r1"),
        (0xE101, "secp521r1"),
        (0xE101, "brainpoolp256r1"),
        (0xE101, "brainpoolp384r1"),
        (0xE101, "brainpoolp512r1"),
        (0xE102, "secp256r1"),
        (0xE102, "secp384r1"),
        (0xE102, "secp521r1"),
        (0xE102, "brainpoolp256r1"),
        (0xE102, "brainpoolp384r1"),
        (0xE102, "brainpoolp512r1"),
        (0xE103, "secp256r1"),
        (0xE103, "secp384r1"),
        (0xE103, "secp521r1"),
        (0xE103, "brainpoolp256r1"),
        (0xE103, "brainpoolp384r1"),
        (0xE103, "brainpoolp512r1"),
    ],
)
def test_keypair_x_y_public_key_import(oid, curve):
    key_object = objects.ECCKey(oid)
    pkey, _ = optiga_ec.generate_pair(key_object, curve=curve)
    parsed_key = serialization.load_der_public_key(pkey, backend=default_backend())
    assert isinstance(parsed_key, ec.EllipticCurvePublicKey)


def test_keypair_faulty():
    with pytest.raises(ValueError):
        key_object = objects.ECCKey(0xE0F1)
        pkey, _ = optiga_ec.generate_pair(key_object, curve="secp384")

    with pytest.raises(ValueError):
        key_object = objects.ECCKey(0xE0FC)
        pkey, _ = optiga_ec.generate_pair(key_object, curve="secp384r1")

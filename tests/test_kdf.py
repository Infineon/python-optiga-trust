# SPDX-FileCopyrightText: 2021-2024 Infineon Technologies AG
# SPDX-License-Identifier: MIT

import pytest
import optigatrust.objects as objects
import optigatrust.crypto as optiga_ec

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

secret = "BFB770EEBF8F61C704E00D828B7A3641D5CD7A3846DEF90F214240250AAF9C2E"
seed = "61C7DEF90FD5CD7A8B7A364104E00D823846BFB770EEBF8F40252E0A2142AF9C"


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
def test_tls_prf(hash_alg, hazmat_curve, curve):
    key = objects.ECCKey(0xE0F1)
    _, _ = optiga_ec.generate_pair(key, curve=curve)
    private_key = ec.generate_private_key(hazmat_curve, default_backend())
    peer_public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    session_object = optiga_ec.ecdh(key, peer_public_key)
    derived_key = optiga_ec.tls_prf(
        session_object, 32, seed=bytes().fromhex(seed), hash_algorithm=hash_alg, export=True
    )

    assert derived_key is not None


@pytest.mark.parametrize("hash_alg", ["sha256", "sha384", "sha512"])
def test_tls_prf_secret_from_appdata(hash_alg):
    app_data = objects.AppData(0xF1D0)
    app_data.write(bytes().fromhex(secret))
    old_type = app_data.meta["type"]
    old_execute_ac = app_data.meta["execute"]
    app_data.meta = {"type": "pre_sh_secret", "execute": "always"}
    derived_key = optiga_ec.tls_prf(
        app_data,
        32,
        label="Firmware update",
        seed=bytes().fromhex(seed),
        hash_algorithm=hash_alg,
        export=True,
    )
    app_data.meta = {"type": old_type, "execute": old_execute_ac}

    assert derived_key is not None


@pytest.mark.parametrize("hash_alg", ["sha256", "sha384", "sha512"])
def test_tls_prf_secret_from_appdata_minimum(hash_alg):
    app_data = objects.AppData(0xF1D0)
    app_data.write(bytes().fromhex(secret))
    old_type = app_data.meta["type"]
    old_execute_ac = app_data.meta["execute"]
    app_data.meta = {"type": "pre_sh_secret", "execute": "always"}
    optiga_ec.tls_prf(app_data, 32, seed=bytes().fromhex(seed), hash_algorithm=hash_alg)
    app_data.meta = {"type": old_type, "execute": old_execute_ac}


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
def test_hkdf(hash_alg, hazmat_curve, curve):
    key = objects.ECCKey(0xE0F1)
    _, _ = optiga_ec.generate_pair(key, curve=curve)
    private_key = ec.generate_private_key(hazmat_curve, default_backend())
    peer_public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    session_object = optiga_ec.ecdh(key, peer_public_key)
    derived_key = optiga_ec.hkdf(session_object, 32, hash_algorithm=hash_alg, export=True)

    assert derived_key is not None


@pytest.mark.parametrize("hash_alg", ["sha256", "sha384", "sha512"])
def test_hkdf_secret_from_appdata(hash_alg):
    app_data = objects.AppData(0xF1D0)
    app_data.write(bytes().fromhex(secret))
    old_type = app_data.meta["type"]
    old_execute_ac = app_data.meta["execute"]
    app_data.meta = {"type": "pre_sh_secret", "execute": "always"}
    derived_key = optiga_ec.hkdf(app_data, 32, hash_algorithm=hash_alg, export=True)
    app_data.meta = {"type": old_type, "execute": old_execute_ac}

    assert derived_key is not None

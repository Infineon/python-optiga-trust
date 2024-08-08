# SPDX-FileCopyrightText: 2021-2024 Infineon Technologies AG
# SPDX-License-Identifier: MIT

import pytest
from optigatrust import crypto, objects


def test_keypair_1k():
    k = objects.RSAKey(0xE0FC)
    pkey, _ = crypto.generate_pair(key_object=k, key_size=1024)
    assert isinstance(pkey, bytes)
    assert len(pkey) > 0
    assert k.key_size == 1024


@pytest.mark.parametrize("ki", [0xE0FC, 0xE0FD])
def test_keypair_1k_keyid(ki):
    k = objects.RSAKey(ki)
    pkey, _ = crypto.generate_pair(key_object=k, key_size=1024)
    assert isinstance(pkey, bytes)
    assert len(pkey) > 0
    assert k.id == ki
    assert k.key_size == 1024


def test_keypair_2k():
    k = objects.RSAKey(0xE0FC)
    pkey, _ = crypto.generate_pair(key_object=k, key_size=2048)
    assert isinstance(pkey, bytes)
    assert len(pkey) > 0
    assert k.id == 0xE0FC
    assert k.key_size == 2048


@pytest.mark.parametrize("ki", [0xE0FC, 0xE0FD])
def test_keypair_2k_keyid(ki):
    k = objects.RSAKey(ki)
    pkey, _ = crypto.generate_pair(key_object=k, key_size=2048)
    assert isinstance(pkey, bytes)
    assert len(pkey) > 0
    assert k.id == ki
    assert k.key_size == 2048


def test_keypair_faulty():
    with pytest.raises(ValueError):
        k = objects.RSAKey(0xE0FC)
        crypto.generate_pair(key_object=k, key_size=100)

    with pytest.raises(ValueError):
        objects.RSAKey(0xE0F1)

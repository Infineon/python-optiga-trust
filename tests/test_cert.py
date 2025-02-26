# SPDX-FileCopyrightText: 2021-2024 Infineon Technologies AG
# SPDX-License-Identifier: MIT

import pytest
import os
import optigatrust.objects as optiga_objects
import asn1crypto.x509 as asn1_x509
import asn1crypto.pem as asn1_pem

pytest.test_dir = os.path.dirname(__file__)


def test_read_existing():
    c = optiga_objects.X509(0xE0E0)
    assert isinstance(c.der, bytes)


def test_read_existing_multiple_times():
    c = optiga_objects.X509(0xE0E0)
    _ = c.pem
    _ = c.pem
    _ = c.pem
    _ = c.pem
    _ = c.pem


def test_read_existing_verify_result():
    c = optiga_objects.X509(0xE0E0)

    der_bytes = c.der
    asn1_x509.Certificate.load(der_bytes)

    pem_str = c.pem
    _, _, der_str = asn1_pem.unarmor(pem_str)
    asn1_x509.Certificate.load(der_str)


def test_read_existing_faulty_objid():
    with pytest.raises(ValueError):
        optiga_objects.X509(0xE0E7)


def test_write_new_default():
    with pytest.raises(IOError):
        with open(os.path.join(pytest.test_dir, "fixtures/test-ec-ecdsa-cert.pem"), "rb") as f:
            pem_bytes = f.read()
        optiga_objects.X509(0xE0E0).pem = pem_bytes


def test_write_new_specific():
    with open(os.path.join(pytest.test_dir, "fixtures/test-ec-ecdsa-cert.pem"), "rb") as f:
        pem_bytes = f.read()
    obj = optiga_objects.X509(0xE0E1)
    old_meta = {"change": obj.meta["change"]}
    obj.meta = {"change": "always"}
    optiga_objects.X509(0xE0E1).pem = pem_bytes
    obj.meta = old_meta


def test_write_new_faulty_objid():
    with pytest.raises(ValueError):
        with open(os.path.join(pytest.test_dir, "fixtures/test-ec-ecdsa-cert.pem"), "rb") as f:
            pem_bytes = f.read()

        optiga_objects.X509(0xE0EC).pem = pem_bytes


def test_write_new_faulty_cert():
    with pytest.raises(ValueError):
        with open(
            os.path.join(pytest.test_dir, "fixtures/test-ec-ecdsa-faulty-cert.pem"), "rb"
        ) as f:
            pem_bytes = f.read()

        optiga_objects.X509(0xE0E1).pem = pem_bytes


def test_write_new_locked_object():
    c = optiga_objects.X509(0xE0E1)
    old_meta = c.meta["change"]
    with pytest.raises(IOError):
        with open(os.path.join(pytest.test_dir, "fixtures/test-ec-ecdsa-cert.pem"), "rb") as f:
            pem_bytes = f.read()

        c.meta = {"change": "never"}
        c.pem = pem_bytes

    c.meta = {"change": old_meta}

import pytest
import os
import optigatrust.x509 as optiga_x509
import asn1crypto.x509 as asn1_x509
import asn1crypto.pem as asn1_pem
import logging

LOGGER = logging.getLogger(__name__)
pytest.test_dir = os.path.dirname(__file__)


def test_read_existing():
    LOGGER.info('Read Certificate')
    c = optiga_x509.Certificate(0xe0e0)
    assert isinstance(c.der, bytes)


def test_read_existing_multiple_times():
    LOGGER.info('Read Certificate multiple times')
    c = optiga_x509.Certificate(0xe0e0)
    _ = c.pem
    _ = c.pem
    _ = c.pem
    _ = c.pem
    _ = c.pem


def test_read_existing_verify_result():
    LOGGER.info('Read certificate and make sanity/format check')
    c = optiga_x509.Certificate(0xe0e0)
    pem_str = c.pem
    if asn1_pem.detect(pem_str):
        type_name, headers, pem_str = asn1_pem.unarmor(pem_str)
    asn1_x509.Certificate.load(pem_str)
    der_bytes = c.der
    asn1_x509.Certificate.load(der_bytes)


def test_read_existing_faulty_objid():
    LOGGER.info('Try to read a incorrect Object ID')
    with pytest.raises(ValueError):
        optiga_x509.Certificate(0xe0e7)


def test_write_new_default():
    LOGGER.info('Write new certificate in a default slot')
    with pytest.raises(IOError):
        with open(os.path.join(pytest.test_dir, 'fixtures/test-ec-ecdsa-cert.pem'), 'rb') as f:
            der_bytes = f.read()
        optiga_x509.Certificate(0xe0e0).der = der_bytes


def test_write_new_specific():
    LOGGER.info('Write new certificate in a specific slot')
    with open(os.path.join(pytest.test_dir, 'fixtures/test-ec-ecdsa-cert.pem'), 'rb') as f:
        der_bytes = f.read()
    obj = optiga_x509.Certificate(0xe0e1)
    old_meta = {'change': obj.meta['change']}
    obj.meta = {'change': 'always'}
    optiga_x509.Certificate(0xe0e1).der = der_bytes
    obj.meta = old_meta


def test_write_new_faulty_objid():
    LOGGER.info('Write new certificate in a fault Certificate Slot')
    with pytest.raises(ValueError):
        with open(os.path.join(pytest.test_dir, 'fixtures/test-ec-ecdsa-cert.pem'), 'rb') as f:
            wr_bytes = f.read()

        optiga_x509.Certificate(0xe0ec).der = wr_bytes


def test_write_new_faulty_cert():
    LOGGER.info('Try to write an false formated certificate')
    with pytest.raises(ValueError):
        with open(os.path.join(pytest.test_dir, 'fixtures/test-ec-ecdsa-faulty-cert.pem'), 'rb') as f:
            wr_bytes = f.read()

        optiga_x509.Certificate(0xe0e1).pem = wr_bytes


def test_write_new_locked_object():
    LOGGER.info('Try to write a certificate into a locked object')
    c = optiga_x509.Certificate(0xe0e1)
    old_meta = c.meta['change']
    with pytest.raises(IOError):
        with open(os.path.join(pytest.test_dir, 'fixtures/test-ec-ecdsa-cert.pem'), 'rb') as f:
            wr_bytes = f.read()

        c.meta = {"change": "never"}
        c.der = wr_bytes

    c.meta = {'change': old_meta}

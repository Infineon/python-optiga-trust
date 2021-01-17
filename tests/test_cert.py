import pytest
import os
from optigatrust.cert import *
from asn1crypto import pem, x509
import logging

LOGGER = logging.getLogger(__name__)
pytest.test_dir = os.path.dirname(__file__)


def test_read_existing():
    LOGGER.info('Read Certificate')
    c = Certificate(0xe0e0)
    assert isinstance(c.der, bytes)


def test_read_existing_multiple_times():
    LOGGER.info('Read Certificate multiple times')
    c = Certificate(0xe0e0)
    _ = c.pem
    _ = c.pem
    _ = c.pem
    _ = c.pem
    _ = c.pem


def test_read_existing_verify_result():
    LOGGER.info('Read certificate and make sanity/format check')
    c = Certificate(0xe0e0)
    pem_str = c.pem
    if pem.detect(pem_str):
        type_name, headers, pem_str = pem.unarmor(pem_str)
    x509.Certificate.load(pem_str)
    der_bytes = c.der
    x509.Certificate.load(der_bytes)


def test_read_existing_faulty_objid():
    LOGGER.info('Try to read a incorrect Object ID')
    with pytest.raises(ValueError):
        Certificate(0xe0e7)


def test_read_default_empty():
    LOGGER.info('Try to read an empty certificate')
    with pytest.raises(ValueError):
        Certificate(0xe0e8)


def test_write_new_default():
    LOGGER.info('Write new certificate in a default slot')
    with pytest.raises(ValueError):
        with open(os.path.join(pytest.test_dir, 'fixtures/test-ec-ecdsa-cert.pem'), 'rb') as f:
            der_bytes = f.read()
        Certificate(0xe0e0).der = der_bytes


def test_write_new_specific():
    LOGGER.info('Write new certificate in a specific slot')
    with open(os.path.join(pytest.test_dir, 'fixtures/test-ec-ecdsa-cert.pem'), 'rb') as f:
        der_bytes = f.read()
    Certificate(0xe0e1).der = der_bytes


def test_write_new_faulty_objid():
    LOGGER.info('Write new certificate in a fault Certificate Slot')
    with pytest.raises(ValueError):
        with open(os.path.join(pytest.test_dir, 'fixtures/test-ec-ecdsa-cert.pem'), 'rb') as f:
            wr_bytes = f.read()

        Certificate(0xe0e9).der = wr_bytes


def test_write_new_faulty_cert():
    LOGGER.info('Try to write an false formated certificate')
    with pytest.raises(ValueError):
        with open(os.path.join(pytest.test_dir, 'fixtures/test-ec-ecdsa-faulty-cert.pem'), 'rb') as f:
            wr_bytes = f.read()

        Certificate(0xe0e1).der = wr_bytes


def test_write_new_locked_object():
    LOGGER.info('Try to write a certificate into a locked object')
    c = Certificate(0xe0e1)
    old_meta = c.meta['change']
    with pytest.raises(ValueError):
        with open(os.path.join(pytest.test_dir, 'fixtures/test-ec-ecdsa-cert.pem'), 'rb') as f:
            wr_bytes = f.read()

        c.meta = {"change": "never"}
        c.der = wr_bytes

    c.meta = {'change': old_meta}


'''
This Test somehow crashes the python
def test_write_new_then_read():
	rd_bytes = cert.read_existing(certid=ObjectId.USER_CERT_1)

	with open(os.path.join(pytest.test_dir, 'fixtures/test-ec-ecdsa-cert.pem'), 'rb') as f:
		wr_bytes = f.read()

	cert.write_new(wr_bytes, certid=ObjectId.USER_CERT_1)

	assert rd_bytes == wr_bytes
'''

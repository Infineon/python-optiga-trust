import pytest
import os
from optigatrust import chip
from asn1crypto import pem, x509
import logging

LOGGER = logging.getLogger(__name__)
pytest.test_dir = os.path.dirname(__file__)


def test_read_existing():
	LOGGER.info('Read Certificate')
	c = chip.read_cert()
	assert isinstance(c, bytes)
	c = chip.read_cert()
	assert isinstance(c, bytes)


def test_read_existing_multiple_times():
	LOGGER.info('Read Certificate multiple times')
	chip.read_cert()
	chip.read_cert()
	chip.read_cert()
	chip.read_cert()
	chip.read_cert()


def test_read_existing_verify_result():
	LOGGER.info('Read certificate and make sanity/format check')
	pem_str = chip.read_cert(to_pem=True)
	if pem.detect(pem_str):
		type_name, headers, pem_str = pem.unarmor(pem_str)
	x509.Certificate.load(pem_str)
	der_bytes = chip.read_cert()
	x509.Certificate.load(der_bytes)


def test_read_existing_faulty_objid():
	LOGGER.info('Try to read a incorrect Object ID')
	with pytest.raises(TypeError):
		chip.read_cert(cert_id=0xE0E7)


def test_read_default_empty():
	LOGGER.info('Try to read an empty certificate')
	with pytest.raises(ValueError):
		chip.read_cert(cert_id=0xe0e8)


def test_write_new_default():
	LOGGER.info('Write new certificate in a default slot')
	with open(os.path.join(pytest.test_dir, '../fixtures/test-ec-ecdsa-cert.pem'), 'rb') as f:
		der_bytes = f.read()
	chip.write_cert(der_bytes)


def test_write_new_specific():
	LOGGER.info('Write new certificate in a specific slot')
	with open(os.path.join(pytest.test_dir, '../fixtures/test-ec-ecdsa-cert.pem'), 'rb') as f:
		der_bytes = f.read()
	chip.write_cert(der_bytes, cert_id=0xe0e1)


def test_write_new_faulty_objid():
	LOGGER.info('Write new certificate in a fault Certificate Slot')
	with pytest.raises(ValueError):
		with open(os.path.join(pytest.test_dir, '../fixtures/test-ec-ecdsa-cert.pem'), 'rb') as f:
			wr_bytes = f.read()

		chip.write_cert(wr_bytes, cert_id=0xE0E0)


def test_write_new_faulty_cert():
	LOGGER.info('Try to write an false formated certificate')
	with pytest.raises(ValueError):
		with open(os.path.join(pytest.test_dir, '../fixtures/test-ec-ecdsa-faulty-cert.pem'), 'rb') as f:
			wr_bytes = f.read()

		chip.write_cert(wr_bytes, cert_id=0xe0e1)


def test_write_new_locked_object():
	LOGGER.info('Try to write a certificate into a locked object')
	with pytest.raises(ValueError):
		with open(os.path.join(pytest.test_dir, '../fixtures/test-ec-ecdsa-cert.pem'), 'rb') as f:
			wr_bytes = f.read()

		chip.write_cert(wr_bytes, 0xe0e0)


'''
This Test somehow crashes the python
def test_write_new_then_read():
	rd_bytes = cert.read_existing(certid=ObjectId.USER_CERT_1)

	with open(os.path.join(pytest.test_dir, 'fixtures/test-ec-ecdsa-cert.pem'), 'rb') as f:
		wr_bytes = f.read()

	cert.write_new(wr_bytes, certid=ObjectId.USER_CERT_1)

	assert rd_bytes == wr_bytes
'''
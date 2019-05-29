import pytest
import os
from optigatrust.x509 import cert
from optigatrust.util.types import *
from asn1crypto import pem, x509

pytest.test_dir = os.path.dirname(__file__)


def test_read_existing_multiple_times():
	cert.read_existing(to_pem=True)
	cert.read_existing(to_pem=True)
	cert.read_existing(to_pem=True)
	cert.read_existing(to_pem=True)
	cert.read_existing(to_pem=True)


def test_read_existing():
	c = cert.read_existing()
	assert isinstance(c, bytes)
	c = cert.read_existing(to_pem=True)
	assert isinstance(c, bytes)


def test_read_existing_verify_result():
	pem_str = cert.read_existing(to_pem=True)
	if pem.detect(pem_str):
		type_name, headers, pem_str = pem.unarmor(pem_str)

	x509.Certificate.load(pem_str)

	der_bytes = cert.read_existing()

	x509.Certificate.load(der_bytes)


def test_read_existing_faulty_objid():
	with pytest.raises(TypeError):
		cert.read_existing(certid=0xE0E1)


def test_read_default_empty():
	with pytest.raises(ValueError):
		cert.read_existing(certid=ObjectId.USER_CERT_3)


def test_write_new_default():
	with open(os.path.join(pytest.test_dir, 'fixtures/test-ec-ecdsa-cert.pem'), 'rb') as f:
		der_bytes = f.read()
	cert.write_new(der_bytes)


def test_write_new_specific():
	with open(os.path.join(pytest.test_dir, 'fixtures/test-ec-ecdsa-cert.pem'), 'rb') as f:
		der_bytes = f.read()
	cert.write_new(der_bytes, certid=ObjectId.USER_CERT_1)


def test_write_new_faulty_objid():
	with pytest.raises(TypeError):
		with open(os.path.join(pytest.test_dir, 'fixtures/test-ec-ecdsa-cert.pem'), 'rb') as f:
			wr_bytes = f.read()

		cert.write_new(wr_bytes, certid=0xE0E0)


def test_write_new_faulty_cert():
	with pytest.raises(ValueError):
		with open(os.path.join(pytest.test_dir, 'fixtures/test-ec-ecdsa-faulty-cert.pem'), 'rb') as f:
			wr_bytes = f.read()

		cert.write_new(wr_bytes, certid=ObjectId.USER_CERT_1)


def test_write_new_locked_object():
	with pytest.raises(ValueError):
		with open(os.path.join(pytest.test_dir, 'fixtures/test-ec-ecdsa-cert.pem'), 'rb') as f:
			wr_bytes = f.read()

		cert.write_new(wr_bytes, certid=ObjectId.IFX_CERT)


'''
This Test somehow crashes the python
def test_write_new_then_read():
	rd_bytes = cert.read_existing(certid=ObjectId.USER_CERT_1)

	with open(os.path.join(pytest.test_dir, 'fixtures/test-ec-ecdsa-cert.pem'), 'rb') as f:
		wr_bytes = f.read()

	cert.write_new(wr_bytes, certid=ObjectId.USER_CERT_1)

	assert rd_bytes == wr_bytes
'''
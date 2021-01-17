import pytest
from oscrypto.asymmetric import rsa_pkcs1v15_verify, load_public_key
from oscrypto.errors import SignatureError
from asn1crypto import keys, core

from optigatrust.asymmetric import *

import logging

LOGGER = logging.getLogger(__name__)

pytest.onek, pytest.onek_fail, pytest.twok, pytest.twok_fail = None, None, None, None
pytest.tbs_str = b'Test String to Sign'
pytest.tbs_str_fail = b'FAILED Test String to Sign'


def setup_keys_1k():
	pytest.onek = RsaKey(0xe0fc).generate(key_size='1024')
	pytest.onek_fail = RsaKey(0xe0fd).generate(key_size='1024')


def setup_keys_2k():
	pytest.twok = RsaKey(0xe0fc).generate(key_size='2048')
	pytest.twok_fail = RsaKey(0xe0fd).generate(key_size='1024')


def test_rsassa_checkcopy():
	LOGGER.info('Sign data with newly generated RSA1k key and check return value')
	setup_keys_1k()
	s = pytest.onek.pkcs1v15_sign(pytest.tbs_str)
	assert s.id is pytest.onek.id


def test_rsassa_1k_sha256():
	LOGGER.info('Sign data with newly generated RSA1k key and SHA256')
	setup_keys_1k()
	s = pytest.onek.pkcs1v15_sign(pytest.tbs_str)
	assert isinstance(s.signature, bytes)
	assert len(s.signature) > 0
	assert s.hash_alg == 'sha256'
	assert s.algorithm == 'sha256_rsa'


def test_rsassa_2k_sha256():
	LOGGER.info('Sign data with newly generated RSA2k key SHA256')
	setup_keys_2k()
	s =  pytest.twok.pkcs1v15_sign(pytest.tbs_str)
	assert isinstance(s.signature, bytes)
	assert len(s.signature) > 0
	assert s.hash_alg == 'sha256'
	assert s.algorithm == 'sha256_rsa'


def test_rsassa_1k_sha384():
	LOGGER.info('Sign data with newly generated RSA1k key and SHA384')
	setup_keys_1k()
	s = pytest.onek.pkcs1v15_sign(pytest.tbs_str, hash_algorithm='sha384')
	assert isinstance(s.signature, bytes)
	assert len(s.signature) > 0
	assert s.hash_alg == 'sha384'
	assert s.algorithm == 'sha384_rsa'


def test_rsassa_2k_sha384():
	LOGGER.info('Sign data with newly generated RSA2k key and SHA384')
	setup_keys_2k()
	s = pytest.twok.pkcs1v15_sign(pytest.tbs_str, hash_algorithm='sha384')
	assert isinstance(s.signature, bytes)
	assert len(s.signature) > 0
	assert s.hash_alg == 'sha384'
	assert s.algorithm == 'sha384_rsa'


def test_1k_signverify():
	LOGGER.info('Sign data with newly generated RSA1k key and verify result')
	setup_keys_1k()
	ha = 'sha256'
	s = pytest.onek.pkcs1v15_sign(pytest.tbs_str)
	#print('[{}]'.format(', '.join(hex(x) for x in list(s.signature))))

	pubkey_info = keys.PublicKeyInfo.load(pytest.onek.pkey)

	# Load a public key into the oscrypto engine to using it in the verify function
	public = load_public_key(pubkey_info)

	rsa_pkcs1v15_verify(public, s.signature, pytest.tbs_str, ha)

	# Assert wrong text
	with pytest.raises(SignatureError):
		rsa_pkcs1v15_verify(public, s.signature, pytest.tbs_str_fail, ha)

	# Assert wrong key
	with pytest.raises(SignatureError):
		pubkey_info = keys.PublicKeyInfo.load(pytest.onek_fail.pkey)
		public = load_public_key(pubkey_info)
		rsa_pkcs1v15_verify(public, s.signature, pytest.tbs_str, ha)


def test_2k_signverify():
	LOGGER.info('Sign data with newly generated RSA2k key and verify result')
	setup_keys_2k()
	ha = 'sha256'
	s = pytest.twok.pkcs1v15_sign(pytest.tbs_str)
	print('[{}]'.format(', '.join(hex(x) for x in list(s.signature))))

	pubkey_info = keys.PublicKeyInfo.load(pytest.twok.pkey)

	# Load a public key into the oscrypto engine to using it in the verify function
	public = load_public_key(pubkey_info)

	rsa_pkcs1v15_verify(public, s.signature, pytest.tbs_str, ha)

	# Assert wrong text
	with pytest.raises(SignatureError):
		rsa_pkcs1v15_verify(public, s.signature, pytest.tbs_str_fail, ha)

	# Assert wrong key
	with pytest.raises(SignatureError):
		pubkey_info = keys.PublicKeyInfo.load(pytest.twok_fail.pkey)
		public = load_public_key(pubkey_info)
		rsa_pkcs1v15_verify(public, s.signature, pytest.tbs_str, ha)


def test_rsassa_nonkey_2():
	LOGGER.info('Sign faulty data with a correct key')
	setup_keys_1k()
	with pytest.raises(TypeError):
		pytest.onek.pkcs1v15_sign(int(19273917398739829))


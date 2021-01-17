import pytest
from oscrypto.asymmetric import ecdsa_verify, load_public_key
from oscrypto.errors import SignatureError
from asn1crypto import keys, core

from optigatrust.asymmetric import *

import logging

LOGGER = logging.getLogger(__name__)

pytest.p256 = None
pytest.p256_fail = None
pytest.p384 = None
pytest.p384_fail = None
tbs_str = b'Test String to Sign'
tbs_str_fail = b'FAILED Test String to Sign'


def setup_keys():
	pytest.p256 = EccKey(0xE100).generate(curve='secp256r1')
	pytest.p256_fail = EccKey(0xE101).generate(curve='secp256r1')
	pytest.p384 = EccKey(0xE102).generate(curve='secp384r1')
	pytest.p384_fail = EccKey(0xE103).generate(curve='secp384r1')


def test_ecdsa_checkcopy():
	LOGGER.info('Sign data with newly generated NIST P-256 key and check return value')
	setup_keys()
	s = pytest.p256.ecdsa_sign(tbs_str)
	assert s.id == pytest.p256.id


def test_ecdsa_p256():
	LOGGER.info('Sign data with newly generated NIST P-256 key')
	setup_keys()
	s = pytest.p256.ecdsa_sign(tbs_str)
	assert isinstance(s.signature, bytes)
	assert len(s.signature) > 0
	assert len(s.signature) <= 72
	assert s.hash_alg == 'sha256'
	assert s.algorithm == 'sha256_ecdsa'


def test_ecdsa_p384():
	LOGGER.info('Sign data with newly generated NIST P-384 key')
	setup_keys()
	s = pytest.p384.ecdsa_sign(tbs_str)
	assert isinstance(s.signature, bytes)
	assert len(s.signature) > 0
	assert len(s.signature) <= 104
	assert s.hash_alg == 'sha384'
	assert s.algorithm == 'sha384_ecdsa'


def test_ecdsa_p256_signverify():
	LOGGER.info('Sign data with newly generated NIST P-256 key and verify result')
	setup_keys()
	ha = 'sha256'
	s = pytest.p256.ecdsa_sign(tbs_str)
	print('[{}]'.format(', '.join(hex(x) for x in list(s.signature))))

	# Preparing an algoroithm
	pubkey_alg = keys.PublicKeyAlgorithm({
		'algorithm': keys.PublicKeyAlgorithmId('ec'),
		'parameters': keys.ECDomainParameters(
			name='named',
			value=pytest.p256.curve
		)
	})

	# Preparing a PublicKeyInfo
	pubkey_asn1 = core.BitString.load(pytest.p256.pkey)
	pubkey_info = keys.PublicKeyInfo({
		'algorithm': pubkey_alg,
		'public_key': pubkey_asn1.cast(keys.ECPointBitString)
	})

	# Load a public key into the oscrypto engine to using it in the verify function
	public = load_public_key(pubkey_info)

	ecdsa_verify(public, s.signature, tbs_str, ha)

	# Assert wrong text
	with pytest.raises(SignatureError):
		ecdsa_verify(public, s.signature, tbs_str_fail, ha)

	# Assert wrong key
	with pytest.raises(SignatureError):
		# Preparing a PublicKeyInfo
		pubkey_asn1 = core.BitString.load(pytest.p256_fail.pkey)
		pubkey_info = keys.PublicKeyInfo({
			'algorithm': pubkey_alg,
			'public_key': pubkey_asn1.cast(keys.ECPointBitString)
		})

		# Load a public key into the oscrypto engine to using it in the verify function
		public = load_public_key(pubkey_info)
		ecdsa_verify(public, s.signature, tbs_str, ha)


def test_ecdsa_p384_signverify():
	LOGGER.info('Sign data with newly generated NIST P-384 key and verify result')
	setup_keys()
	ha = 'sha384'
	s = pytest.p384.ecdsa_sign(tbs_str)
	print('[{}]'.format(', '.join(hex(x) for x in list(s.signature))))

	# Preparing an algoroithm
	pubkey_alg = keys.PublicKeyAlgorithm({
		'algorithm': keys.PublicKeyAlgorithmId('ec'),
		'parameters': keys.ECDomainParameters(
			name='named',
			value=pytest.p384.curve
		)
	})

	# Preparing a PublicKeyInfo
	pubkey_asn1 = core.BitString.load(pytest.p384.pkey)
	pubkey_info = keys.PublicKeyInfo({
		'algorithm': pubkey_alg,
		'public_key': pubkey_asn1.cast(keys.ECPointBitString)
	})

	# Load a public key into the oscrypto engine to using it in the verify function
	public = load_public_key(pubkey_info)

	# Assert wrong text
	with pytest.raises(SignatureError):
		ecdsa_verify(public, s.signature, tbs_str_fail, ha)

	# Assert wrong key
	with pytest.raises(SignatureError):
		# Preparing a PublicKeyInfo
		pubkey_asn1 = core.BitString.load(pytest.p384_fail.pkey)
		pubkey_info = keys.PublicKeyInfo({
			'algorithm': pubkey_alg,
			'public_key': pubkey_asn1.cast(keys.ECPointBitString)
		})

		# Load a public key into the oscrypto engine to using it in the verify function
		public = load_public_key(pubkey_info)
		ecdsa_verify(public, s.signature, tbs_str, ha)


def test_ecdsa_nonkey():
	LOGGER.info('Sign data with empty key')
	setup_keys()
	with pytest.raises(TypeError):
		pytest.p256.ecdsa_sign(bytearray(35), tbs_str)


def test_ecdsa_nonkey_2():
	LOGGER.info('Sign faulty data with a correct key')
	setup_keys()
	with pytest.raises(TypeError):
		pytest.p256.ecdsa_sign(int(19273917398739829))


import pytest
from oscrypto.asymmetric import rsa_pkcs1v15_verify, load_public_key
from oscrypto.errors import SignatureError
from asn1crypto import keys

from optigatrust import objects, crypto

pytest.onek, pytest.onek_fail, pytest.twok, pytest.twok_fail = None, None, None, None
k1, k2 = None, None
pytest.tbs_str = b'Test String to Sign'
pytest.tbs_str_fail = b'FAILED Test String to Sign'


def setup_keys_1k():
	k1 = objects.RSAKey(0xe0fc)
	k2 = objects.RSAKey(0xe0fd)
	pytest.onek, _ = crypto.generate_pair(key_object=k1, key_size=1024)
	pytest.onek_fail, _ = crypto.generate_pair(key_object=k2, key_size=1024)
	return k1, k2


def setup_keys_2k():
	k1 = objects.RSAKey(0xe0fc)
	k2 = objects.RSAKey(0xe0fd)
	pytest.twok, _ = crypto.generate_pair(key_object=k1, key_size=2048)
	pytest.twok_fail, _ = crypto.generate_pair(key_object=k2, key_size=2048)
	return k1, k2


def test_rsassa_checkcopy():
	k1, _ = setup_keys_1k()
	crypto.pkcs1v15_sign(k1, pytest.tbs_str)


def test_rsassa_1k_sha256():
	k1, _ = setup_keys_1k()
	s = crypto.pkcs1v15_sign(k1, pytest.tbs_str)
	assert isinstance(s.signature, bytes)
	assert len(s.signature) > 0
	assert s.hash_alg == 'sha256'
	assert s.algorithm == 'sha256_rsa'


def test_rsassa_2k_sha256():
	k1, _ = setup_keys_2k()
	s = crypto.pkcs1v15_sign(k1, pytest.tbs_str)
	assert isinstance(s.signature, bytes)
	assert len(s.signature) > 0
	assert s.hash_alg == 'sha256'
	assert s.algorithm == 'sha256_rsa'


def test_rsassa_1k_sha384():
	k1, _ = setup_keys_1k()
	s = crypto.pkcs1v15_sign(key_object=k1, data=pytest.tbs_str, hash_algorithm='sha384')
	assert isinstance(s.signature, bytes)
	assert len(s.signature) > 0
	assert s.hash_alg == 'sha384'
	assert s.algorithm == 'sha384_rsa'


def test_rsassa_2k_sha384():
	k1, _ = setup_keys_2k()
	s = crypto.pkcs1v15_sign(key_object=k1, data=pytest.tbs_str, hash_algorithm='sha384')
	assert isinstance(s.signature, bytes)
	assert len(s.signature) > 0
	assert s.hash_alg == 'sha384'
	assert s.algorithm == 'sha384_rsa'


def test_1k_signverify():
	k1, k2 = setup_keys_1k()
	ha = 'sha256'
	s = crypto.pkcs1v15_sign(k1, pytest.tbs_str)
	#print('[{}]'.format(', '.join(hex(x) for x in list(s.signature))))

	pubkey_info = keys.PublicKeyInfo.load(pytest.onek)

	# Load a public key into the oscrypto engine to using it in the verify function
	public = load_public_key(pubkey_info)

	rsa_pkcs1v15_verify(public, s.signature, pytest.tbs_str, ha)

	# Assert wrong text
	with pytest.raises(SignatureError):
		rsa_pkcs1v15_verify(public, s.signature, pytest.tbs_str_fail, ha)

	# Assert wrong key
	with pytest.raises(SignatureError):
		pubkey_info = keys.PublicKeyInfo.load(pytest.onek_fail)
		public = load_public_key(pubkey_info)
		rsa_pkcs1v15_verify(public, s.signature, pytest.tbs_str, ha)


def test_2k_signverify():
	k1, k2 = setup_keys_2k()
	ha = 'sha256'
	s = crypto.pkcs1v15_sign(k1, pytest.tbs_str)
	print('[{}]'.format(', '.join(hex(x) for x in list(s.signature))))

	pubkey_info = keys.PublicKeyInfo.load(pytest.twok)

	# Load a public key into the oscrypto engine to using it in the verify function
	public = load_public_key(pubkey_info)

	rsa_pkcs1v15_verify(public, s.signature, pytest.tbs_str, ha)

	# Assert wrong text
	with pytest.raises(SignatureError):
		rsa_pkcs1v15_verify(public, s.signature, pytest.tbs_str_fail, ha)

	# Assert wrong key
	with pytest.raises(SignatureError):
		pubkey_info = keys.PublicKeyInfo.load(pytest.twok_fail)
		public = load_public_key(pubkey_info)
		rsa_pkcs1v15_verify(public, s.signature, pytest.tbs_str, ha)


def test_rsassa_nonkey_2():
	k1, _ = setup_keys_1k()
	with pytest.raises(TypeError):
		crypto.pkcs1v15_sign(k1, int(19273917398739829))


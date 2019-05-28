import pytest
from optigatrust.pk import ecc
from optigatrust.util.types import KeyId, Curves


def test_keypair_default():
	k = ecc.generate_keypair()
	assert isinstance(k.pkey, bytes)
	assert len(k.pkey) > 0
	assert len(k.pkey) == 68
	assert k.algorithm is 'ec'
	assert k.keyid in KeyId
	assert isinstance(k.curve, str)


def test_keypair_nistp256():
	k = ecc.generate_keypair(curve='secp256r1')
	assert isinstance(k.pkey, bytes)
	assert len(k.pkey) > 0
	assert len(k.pkey) == 68
	assert k.algorithm is 'ec'
	assert k.keyid == KeyId.USER_PRIVKEY_1
	assert k.curve == 'secp256r1'


@pytest.mark.parametrize("ki", [
	KeyId.USER_PRIVKEY_1,
	KeyId.USER_PRIVKEY_2,
	KeyId.USER_PRIVKEY_3,
	KeyId.SESSION_ID_1,
	KeyId.SESSION_ID_2,
	KeyId.SESSION_ID_3,
	KeyId.SESSION_ID_4,
])
def test_keypair_nistp256_keyid(ki):
	k = ecc.generate_keypair(curve='secp256r1', keyid=ki)
	assert isinstance(k.pkey, bytes)
	assert len(k.pkey) > 0
	assert len(k.pkey) == 68
	assert k.algorithm is 'ec'
	assert k.keyid == ki
	assert k.curve == 'secp256r1'


def test_keypair_nistp384():
	k = ecc.generate_keypair(curve='secp384r1')
	assert isinstance(k.pkey, bytes)
	assert len(k.pkey) > 0
	assert len(k.pkey) == 100
	assert k.algorithm is 'ec'
	assert k.keyid == KeyId.USER_PRIVKEY_1
	assert k.curve == 'secp384r1'


@pytest.mark.parametrize("ki", [
	KeyId.USER_PRIVKEY_1,
	KeyId.USER_PRIVKEY_2,
	KeyId.USER_PRIVKEY_3,
	KeyId.SESSION_ID_1,
	KeyId.SESSION_ID_2,
	KeyId.SESSION_ID_3,
	KeyId.SESSION_ID_4,
])
def test_keypair_nistp384_keyid(ki):
	k = ecc.generate_keypair(curve='secp384r1', keyid=ki)
	assert isinstance(k.pkey, bytes)
	assert len(k.pkey) > 0
	assert len(k.pkey) == 100
	assert k.algorithm is 'ec'
	assert k.keyid == ki
	assert k.curve == 'secp384r1'


def test_keypair_faulty():
	with pytest.raises(ValueError):
		ecc.generate_keypair(curve='nist256r1')

	with pytest.raises(TypeError):
		ecc.generate_keypair(keyid=0xE0F1)

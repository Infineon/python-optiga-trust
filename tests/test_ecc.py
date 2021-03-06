import pytest
from optigatrust.pk import ecc
from optigatrust.util.types import KeyId
import logging

LOGGER = logging.getLogger(__name__)

def test_keypair_default():
	LOGGER.info('Generate a keypair using default parameters')
	k = ecc.generate_keypair()
	assert isinstance(k.pkey, bytes)
	assert len(k.pkey) > 0
	assert len(k.pkey) == 68
	assert k.algorithm is 'ec'
	assert k.keyid in KeyId
	assert isinstance(k.curve, str)


def test_keypair_nistp256():
	LOGGER.info('Generate a keypair NIST P-256')
	k = ecc.generate_keypair(curve='secp256r1')
	assert isinstance(k.pkey, bytes)
	assert len(k.pkey) > 0
	assert len(k.pkey) == 68
	assert k.algorithm is 'ec'
	assert k.keyid == KeyId.ECC_KEY_E0F1
	assert k.curve == 'secp256r1'


@pytest.mark.parametrize("ki", [
	KeyId.ECC_KEY_E0F1,
	KeyId.ECC_KEY_E0F2,
	KeyId.ECC_KEY_E0F3,
	KeyId.SESSION_ID_1,
	KeyId.SESSION_ID_2,
	KeyId.SESSION_ID_3,
	KeyId.SESSION_ID_4,
])
def test_keypair_nistp256_keyid(ki):
	LOGGER.info('Generate a NIST P-256 keypair for a specific Object ID {0}'.format(ki))
	k = ecc.generate_keypair(curve='secp256r1', keyid=ki)
	assert isinstance(k.pkey, bytes)
	assert len(k.pkey) > 0
	assert len(k.pkey) == 68
	assert k.algorithm is 'ec'
	assert k.keyid == ki
	assert k.curve == 'secp256r1'


def test_keypair_nistp384():
	LOGGER.info('Generate a keypair NIST P-384')
	k = ecc.generate_keypair(curve='secp384r1')
	assert isinstance(k.pkey, bytes)
	assert len(k.pkey) > 0
	assert len(k.pkey) == 100
	assert k.algorithm is 'ec'
	assert k.keyid == KeyId.ECC_KEY_E0F1
	assert k.curve == 'secp384r1'


@pytest.mark.parametrize("ki", [
	KeyId.ECC_KEY_E0F1,
	KeyId.ECC_KEY_E0F2,
	KeyId.ECC_KEY_E0F3,
	KeyId.SESSION_ID_1,
	KeyId.SESSION_ID_2,
	KeyId.SESSION_ID_3,
	KeyId.SESSION_ID_4,
])
def test_keypair_nistp384_keyid(ki):
	LOGGER.info('Generate a NIST P-384 keypair for a specific Object ID {0}'.format(ki))
	k = ecc.generate_keypair(curve='secp384r1', keyid=ki)
	assert isinstance(k.pkey, bytes)
	assert len(k.pkey) > 0
	assert len(k.pkey) == 100
	assert k.algorithm is 'ec'
	assert k.keyid == ki
	assert k.curve == 'secp384r1'


def test_keypair_faulty():
	LOGGER.info('Try to use faulty curves and keyid')
	with pytest.raises(ValueError):
		ecc.generate_keypair(curve='nist256r1')

	with pytest.raises(TypeError):
		ecc.generate_keypair(keyid=0xE0F1)

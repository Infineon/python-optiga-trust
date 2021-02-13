import pytest
from optigatrust.crypto import RSAKey
import logging

LOGGER = logging.getLogger(__name__)


def test_keypair_default():
	LOGGER.info('Generate a keypair using default parameters')
	k = RSAKey(0xe0fc).generate_pair()
	assert isinstance(k.pkey, bytes)
	assert len(k.pkey) > 0
	assert k.id == 0xe0fc
	assert k.key_size == 1024


def test_keypair_1k():
	LOGGER.info('Generate an RSA1024 keypair')
	k = RSAKey(0xe0fc).generate_pair(key_size=1024)
	assert isinstance(k.pkey, bytes)
	assert len(k.pkey) > 0
	assert k.key_size == 1024


@pytest.mark.parametrize("ki", [
	0xe0fc,
	0xe0fd
])
def test_keypair_1k_keyid(ki):
	LOGGER.info('Generate a RSA1024 keypair for a specific Object ID {0}'.format(ki))
	k =RSAKey(ki).generate_pair(key_size=1024)
	assert isinstance(k.pkey, bytes)
	assert len(k.pkey) > 0
	assert k.id == ki
	assert k.key_size == 1024


def test_keypair_2k():
	LOGGER.info('Generate an RSA2048 keypair')
	k = RSAKey(0xe0fc).generate_pair(key_size=2048)
	assert isinstance(k.pkey, bytes)
	assert len(k.pkey) > 0
	assert k.id == 0xe0fc
	assert k.key_size == 2048


@pytest.mark.parametrize("ki", [
	0xe0fc,
	0xe0fd
])
def test_keypair_2k_keyid(ki):
	LOGGER.info('Generate a RSA2048 keypair for a specific Object ID {0}'.format(ki))
	k = RSAKey(ki).generate_pair(key_size=2048)
	assert isinstance(k.pkey, bytes)
	assert len(k.pkey) > 0
	assert k.id == ki
	assert k.key_size == 2048


def test_keypair_faulty():
	LOGGER.info('Try to use faulty curves and keyid')
	with pytest.raises(ValueError):
		RSAKey(0xe0fc).generate_pair(key_size=100)

	with pytest.raises(ValueError):
		RSAKey(0xe0f1).generate_pair()

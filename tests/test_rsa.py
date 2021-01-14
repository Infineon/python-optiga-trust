import pytest
from optigatrust.asymmetric import *
from optigatrust import chip
import logging

LOGGER = logging.getLogger(__name__)


@pytest.mark.skipif(chip.is_trustm() is False, reason="requires OPTIGA(TM) Trust M")
def test_keypair_default():
	LOGGER.info('Generate a keypair using default parameters')
	k = rsa_generate_keypair()
	assert isinstance(k.pkey, bytes)
	assert len(k.pkey) > 0
	assert k.algorithm is 'rsa'
	assert k.keyid in KeyId
	assert k.key_size == 1024


@pytest.mark.skipif(chip.is_trustm() is False, reason="requires OPTIGA(TM) Trust M")
def test_keypair_1k():
	LOGGER.info('Generate an RSA1024 keypair')
	k = rsa_generate_keypair(key_size='1024')
	assert isinstance(k.pkey, bytes)
	assert len(k.pkey) > 0
	assert k.algorithm is 'rsa'
	assert k.key_size == 1024


@pytest.mark.parametrize("ki", [
	0xe0fc,
	0xe0fd
])
@pytest.mark.skipif(chip.is_trustm() is False, reason="requires OPTIGA(TM) Trust M")
def test_keypair_1k_keyid(ki):
	LOGGER.info('Generate a RSA1024 keypair for a specific Object ID {0}'.format(ki))
	k = rsa_generate_keypair(key_size='1024', keyid=ki)
	assert isinstance(k.pkey, bytes)
	assert len(k.pkey) > 0
	assert k.algorithm is 'rsa'
	assert k.keyid == ki
	assert k.key_size == 1024


@pytest.mark.skipif(chip.is_trustm() is False, reason="requires OPTIGA(TM) Trust M")
def test_keypair_2k():
	LOGGER.info('Generate an RSA2048 keypair')
	k = rsa_generate_keypair(key_size='2048')
	assert isinstance(k.pkey, bytes)
	assert len(k.pkey) > 0
	assert k.algorithm is 'rsa'
	assert k.keyid == 0xe0fc
	assert k.key_size == 2048


@pytest.mark.parametrize("ki", [
	0xe0fc,
	0xe0fd
])
@pytest.mark.skipif(chip.is_trustm() is False, reason="requires OPTIGA(TM) Trust M")
def test_keypair_2k_keyid(ki):
	LOGGER.info('Generate a RSA2048 keypair for a specific Object ID {0}'.format(ki))
	k = rsa_generate_keypair(key_size='2048', keyid=ki)
	assert isinstance(k.pkey, bytes)
	assert len(k.pkey) > 0
	assert k.algorithm is 'rsa'
	assert k.keyid == ki
	assert k.key_size == 2048


@pytest.mark.skipif(chip.is_trustm() is False, reason="requires OPTIGA(TM) Trust M")
def test_keypair_faulty():
	LOGGER.info('Try to use faulty curves and keyid')
	with pytest.raises(ValueError):
		rsa_generate_keypair(key_size='102')

	with pytest.raises(ValueError):
		rsa_generate_keypair(0xe0f1)

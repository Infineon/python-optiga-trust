import pytest
from optigatrust.pk import *
from optigatrust.util import *
from optigatrust.util.types import *
from optigatrust.x509 import *
import logging

LOGGER = logging.getLogger(__name__)


def test_csr_ok():
	LOGGER.info('Build a Certificate Signing Request NIST P-256')
	csr_key = ecc.generate_keypair(curve='secp256r1', keyid=KeyId.ECC_KEY_E0F3)

	csr.Builder(
		{
			'country_name': 'DE',
			'state_or_province_name': 'Bayern',
			'organization_name': 'Infineon Technologies AG',
			'common_name': 'OPTIGA(TM) Trust IoT',
		},
		csr_key
	)


def test_csr_ok_2():
	LOGGER.info('Build a Certificate Signing Request NIST P-384')
	csr_key = ecc.generate_keypair(curve='secp256r1', keyid=KeyId.ECC_KEY_E0F3)

	csr.Builder(
		{
			'country_name': 'DE',
			'state_or_province_name': 'Bayern',
			'organization_name': 'Infineon Technologies AG',
			'common_name': 'OPTIGA(TM) Trust IoT',
		},
		csr_key
	)


@pytest.mark.skipif(chip.is_trustm() is False, reason="requires OPTIGA(TM) Trust M")
def test_csr_ok_3():
	LOGGER.info('Build a Certificate Signing Request RSA1k')
	csr_key = rsa.generate_keypair(key_size='1024', keyid=KeyId.RSA_KEY_E0FC)

	csr.Builder(
		{
			'country_name': 'DE',
			'state_or_province_name': 'Bayern',
			'organization_name': 'Infineon Technologies AG',
			'common_name': 'OPTIGA(TM) Trust IoT',
		},
		csr_key
	)


@pytest.mark.skipif(chip.is_trustm() is False, reason="requires OPTIGA(TM) Trust M")
def test_csr_ok_4():
	LOGGER.info('Build a Certificate Signing Request RSA2k')
	csr_key = rsa.generate_keypair(key_size='2048', keyid=KeyId.RSA_KEY_E0FD)

	csr.Builder(
		{
			'country_name': 'DE',
			'state_or_province_name': 'Bayern',
			'organization_name': 'Infineon Technologies AG',
			'common_name': 'OPTIGA(TM) Trust IoT',
		},
		csr_key
	)
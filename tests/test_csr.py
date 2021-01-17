import pytest
from optigatrust.asymmetric import *
from optigatrust.cert import *
import logging

LOGGER = logging.getLogger(__name__)


def test_csr_ok():
	LOGGER.info('Build a Certificate Signing Request NIST P-256')
	csr_key = EccKey(0xe0f3).generate(curve='secp256r1')

	Builder(
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
	csr_key = EccKey(0xe0f3).generate(curve='secp384r1')

	Builder(
		{
			'country_name': 'DE',
			'state_or_province_name': 'Bayern',
			'organization_name': 'Infineon Technologies AG',
			'common_name': 'OPTIGA(TM) Trust IoT',
		},
		csr_key
	)


def test_csr_ok_3():
	LOGGER.info('Build a Certificate Signing Request RSA1k')
	csr_key = RsaKey(0xe0fc).generate(key_size='1024')

	Builder(
		{
			'country_name': 'DE',
			'state_or_province_name': 'Bayern',
			'organization_name': 'Infineon Technologies AG',
			'common_name': 'OPTIGA(TM) Trust IoT',
		},
		csr_key
	)


def test_csr_ok_4():
	LOGGER.info('Build a Certificate Signing Request RSA2k')
	csr_key = RsaKey(0xe0fc).generate(key_size='2048')

	Builder(
		{
			'country_name': 'DE',
			'state_or_province_name': 'Bayern',
			'organization_name': 'Infineon Technologies AG',
			'common_name': 'OPTIGA(TM) Trust IoT',
		},
		csr_key
	)
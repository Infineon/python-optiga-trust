from optigatrust.pk import *
from optigatrust.util.types import *
from optigatrust.x509 import *
import logging

LOGGER = logging.getLogger(__name__)

def test_csr_ok():
	LOGGER.info('Build a Certificate Signing Request NIST P-256')
	csr_key = ecc.generate_keypair(curve='secp256r1', keyid=KeyId.USER_PRIVKEY_3)

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
	csr_key = ecc.generate_keypair(curve='secp256r1', keyid=KeyId.USER_PRIVKEY_3)

	csr.Builder(
		{
			'country_name': 'DE',
			'state_or_province_name': 'Bayern',
			'organization_name': 'Infineon Technologies AG',
			'common_name': 'OPTIGA(TM) Trust IoT',
		},
		csr_key
	)
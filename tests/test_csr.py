import pytest
from optigatrust.crypto import ECCKey, RSAKey
from optigatrust.x509 import CSRBuilder
import logging

LOGGER = logging.getLogger(__name__)


@pytest.mark.parametrize("ki", [
	'secp256r1', 'secp384r1', 'secp521r1',	'brainpoolp256r1', 'brainpoolp384r1', 'brainpoolp512r1'
])
def test_csr_ecc(ki):
	LOGGER.info('Build a Certificate Signing Request {0}'.format(ki))
	csr_key = ECCKey(0xe0f3).generate(curve=ki)

	builder = CSRBuilder(
		{
			'country_name': 'DE',
			'state_or_province_name': 'Bayern',
			'organization_name': 'Infineon Technologies AG',
			'common_name': 'OPTIGA(TM) Trust IoT',
		},
		csr_key
	)

	builder.build(csr_key)


@pytest.mark.parametrize("ki", [
	1024, 2048
])
def test_csr_ok_rsa(ki):
	LOGGER.info('Build a Certificate Signing Request RSA {0}'.format(ki))
	csr_key = RSAKey(0xe0fc).generate(key_size=ki)

	builder = CSRBuilder(
		{
			'country_name': 'DE',
			'state_or_province_name': 'Bayern',
			'organization_name': 'Infineon Technologies AG',
			'common_name': 'OPTIGA(TM) Trust IoT',
		},
		csr_key
	)

	builder.build(csr_key)
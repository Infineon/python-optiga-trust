import pytest
from optigatrust import objects, crypto
from optigatrust.csr import CSRBuilder


@pytest.mark.parametrize("ki", [
	'secp256r1', 'secp384r1', 'secp521r1',	'brainpoolp256r1', 'brainpoolp384r1', 'brainpoolp512r1'
])
def test_csr_ecc(ki):
	csr_key_obj = objects.ECCKey(0xe0f3)
	pkey, _ = crypto.generate_pair(key_object=csr_key_obj, curve=ki)

	builder = CSRBuilder(
		{
			'country_name': 'DE',
			'state_or_province_name': 'Bayern',
			'organization_name': 'Infineon Technologies AG',
			'common_name': 'OPTIGA(TM) Trust IoT',
		},
		pkey
	)

	builder.build(csr_key_obj)


@pytest.mark.parametrize("ki", [
	1024, 2048
])
def test_csr_ok_rsa(ki):
	csr_key_obj = objects.RSAKey(0xe0fc)
	print(csr_key_obj)
	pkey, _ = crypto.generate_pair(key_object=csr_key_obj, key_size=ki)

	builder = CSRBuilder(
		{
			'country_name': 'DE',
			'state_or_province_name': 'Bayern',
			'organization_name': 'Infineon Technologies AG',
			'common_name': 'OPTIGA(TM) Trust IoT',
		},
		pkey
	)

	builder.build(csr_key_obj)
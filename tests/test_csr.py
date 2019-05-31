from optigatrust.pk import *
from optigatrust.util.types import *
from optigatrust.x509 import *


def test_csr_ok():
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

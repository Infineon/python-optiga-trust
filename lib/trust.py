from optigatrust.rand import *
from optigatrust.pk import *
from optigatrust.x509 import *
import base64

print("Rand size 8 bytes: {0}\n".format(list(get_random_bytes(8))))
print("Rand size 16 bytes: {0}\n".format(list(get_random_bytes(16))))
print("Rand size 255 bytes: {0}\n".format(list(get_random_bytes(255))))

key_1 = ecc.generate_keypair()
print("Generate NIST-P256 Keypair: {0}\n".format(list(key_1.pkey)))

sign_1 = ecdsa.sign(key_1, b'Hello World')
print("Generate ECDSA Signature using the keypair: {0}\n".format(list(sign_1.signature)))

builder = csr.Builder(
	{
		'country_name': 'DE',
		'state_or_province_name': 'Bayern',
		'organization_name': 'Infineon Technologies AG',
		'common_name': 'OPTIGA(TM) Trust X IoT',
	},
	key_1
)

request = builder.build(key_1)

der_bytes = request.dump()

csr = base64.b64encode(der_bytes)

print(csr)
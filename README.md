# A Python package to support the OPTIGA™ Trust devices
# Status - alpha

## Intro
A python ctypes based wrapper for the OPTIGA™ Trust Software Framework

## Hardware
In order to use this package you need to have the OPTIGA™ Trust Personalisation Board

## Compatibility
* MS Windows 32bit/64bit
* Linux (32bit)

## Installation

### Requirements
You need to have at least Python 3+ insalled on you computer before proceeding.
Don't forget to add you Python to the standard path ([for instance](https://geek-university.com/python/add-python-to-the-windows-path/)).

### Flow
The module can be installed via a standard Python Package manager (pip). Type in your terminal

```console
$ pip install optigatrust
```

The module can be updated with the following command
```console
$ pip install -U optigatrust
```

De-installation:
```console
$ pip uninstall optigatrust
```

## Usage examples

```python
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
```

An output might be like this

```
Rand size 8 bytes: [4, 177, 254, 71, 206, 105, 167, 59]

Rand size 16 bytes: [97, 248, 197, 22, 163, 203, 234, 186, 196, 190, 21, 33, 189, 126, 167, 1]

Rand size 255 bytes: [6, 30, 186, 215, 212, 246, 56, 109, 209, 132, 135, 142, 88, 70, 159, 251, 187, 41, 237, 68, 236, 147, 238, 79, 233, 197, 151, 72, 202, 2, 114, 122, 242, 163, 238, 86, 132, 238, 45, 141, 90, 250, 247, 192, 168, 47, 29, 195, 145, 121, 169, 224, 228, 135, 181, 68, 248, 145, 183, 244, 178, 228, 223, 169, 48, 193, 222, 8, 53, 134, 21, 77, 189, 215, 241, 219, 91, 23, 244, 45, 246, 228, 167, 255, 75, 219, 151, 56, 81, 76, 3, 132, 166, 12, 203, 63, 12, 214, 20, 253, 8, 112, 70, 166, 193, 83, 35, 1, 51, 9, 174, 239, 9, 7, 178, 186, 37, 176, 209, 0, 17, 16, 15, 151, 134, 251, 111, 98, 47, 104, 121, 29, 177, 129, 210, 122, 39, 127, 198, 140, 191, 126, 237, 95, 101, 98, 92, 180, 4, 202, 243, 252, 248, 119, 129, 12, 3, 114, 225, 1, 29, 236, 65, 230, 34, 249, 55, 90, 189, 241, 184, 145, 16, 131, 49, 222, 91, 188, 104, 166, 90, 67, 147, 62, 133, 167, 193, 84, 209, 48, 49, 175, 194, 146, 32, 151, 70, 120, 143, 105, 16, 91, 179, 199, 253, 78, 21, 216, 6, 196, 165, 118, 9, 209, 200, 24, 194, 72, 99, 167, 242, 68, 164, 178, 84, 134, 58, 66, 136, 186, 236, 25, 114, 80, 155, 216, 158, 162, 185, 50, 113, 208, 152, 70, 171, 5, 104, 213, 98, 19, 177, 201, 22, 55, 82]

Generate NIST-P256 Keypair: [3, 66, 0, 4, 163, 102, 77, 131, 251, 153, 186, 143, 48, 164, 61, 55, 201, 33, 11, 95, 230, 37, 220, 98, 35, 81, 162, 84, 80, 105, 252, 120, 151, 164, 160, 25, 92, 0, 94, 236, 53, 205, 115, 191, 78, 224, 124, 178, 129, 11, 40, 150, 99, 206, 119, 118, 122, 139, 112, 235, 165, 46, 201, 210, 126, 11, 121, 240]

Generate ECDSA Signature using the keypair: [48, 0, 70, 2, 33, 0, 149, 217, 0, 159, 107, 82, 56, 7, 94, 213, 179, 21, 54, 192, 167, 42, 51, 53, 211, 158, 92, 202, 109, 80, 20, 16, 5, 84, 166, 128, 188, 61, 2, 33, 0, 194, 201, 253, 139, 95, 219, 151, 166, 245, 32, 75, 244, 112, 93, 13, 240, 87, 241, 170, 230, 22, 92, 63, 47, 208, 203, 150, 170, 229, 217, 109, 98]

b'MIIBYDCCAQUCAQAwYjELMAkGA1UEBhMCREUxDzANBgNVBAgMBkJheWVybjEhMB8GA1UECgwYSW5maW5lb24gVGVjaG5vbG9naWVzIEFHMR8wHQYDVQQDDBZPUFRJR0EoVE0pIFRydXN0IFggSW9UME8wCQYHKoZIzj0CAQNCAASjZk2D+5m6jzCkPTfJIQtf5iXcYiNRolRQafx4l6SgGVwAXuw1zXO/TuB8soELKJZjznd2eotw66UuydJ+C3nwoEswSQYJKoZIhvcNAQkOMTwwOjAJBgNVHRMEAjAAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAOBgNVHQ8BAf8EBAMCBaAwCgYIKoZIzj0EAwIDSQAwAEUCIGNXvwohZk8X/bAJbJyXT/IayLbscQwsyNKvjb8stFWZAiEAmpzcpCCgZ/9FUlmLY0SE4hJXyGlRMefsD1xNpqJx94g='
```

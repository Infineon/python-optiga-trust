# optigatrust

A ctypes based Python wrapper to work with the OPTIGA(TM) Trust security solutions.

 - [Features](#features)
 - [Dependencies](#dependencies)
 - [Required Hardware](#required-hardware)
 - [Installation](#installation)
 - [License](#license)
 - [Documentation](#documentation)
 - [Testing](#testing)
 - [Development](#development)

[![PyPI](https://img.shields.io/pypi/v/optigatrust.svg)](https://pypi.org/project/optigatrust/)

## Features

| Function                    | Module                                      |
| --------------------------- | ------------------------------------------- | 
| Elliptic Curves Cryptograpy | [`optigatrust.pk.ecc`](lib/optigatrust/pk/ecc.py)       | 
| ECDSA                       | [`optigatrust.pk.ecdsa`](lib/optigatrust/pk/ecdsa.py)       | 
| Certificate Signing Request | [`optigatrust.x509.csr`](lib/optigatrust/x509/csr.py)     |
| Certificate handling        | [`optigatrust.x509.cert`](lib/optigatrust/x509/cert.py)     | 
| Random Number Generation    | [`optigatrust.rand`](lib/optigatrust/rand/__init__.py)       | 
| Write/Read General Purpose Data | [`optigatrust.util.io`](lib/optigatrust/util/io.py)       | 

## Dependencies

 - Python 3.x 
 - [asn1crypto](https://github.com/wbond/asn1crypto)
 - [oscrypto](https://github.com/wbond/oscrypto)
 
## Required Hardware

- OPTIGA(TM) Trust Personalisation Board, or
- any FTDI USB-HID/I2C Converter board
- (planned) Embedded Linux with open I2C lines; e.g. RPi3

## Installation

```bash
$ pip install optigatrust
```

## License

*optigatrust* is licensed under the terms of the MIT license. See the
[LICENSE](LICENSE) file for the exact license text.

## Documentation

The documentation for *optigatrust* is composed of tutorials on basic usage and
links to the source for the various pre-defined type classes.

### Examples

```python
from optigatrust.util.types import *
from optigatrust.rand import *
from optigatrust.pk import *
from optigatrust.x509 import *
import base64

print("Rand size 8 bytes: {0}\n".format(list(get_random_bytes(8))))
print("Rand size 16 bytes: {0}\n".format(list(get_random_bytes(16))))
print("Rand size 255 bytes: {0}\n".format(list(get_random_bytes(255))))

ecc_key = ecc.generate_keypair()
print("Generate NIST-P256 Keypair: {0}\n".format(list(ecc_key.pkey)))

ecdsa_signature = ecdsa.sign(ecc_key, b'Hello World')
print("Generate ECDSA Signature using the keypair: {0}\n".format(list(ecdsa_signature.signature)))

csr_key = ecc.generate_keypair(curve='secp256r1', keyid=KeyId.USER_PRIVKEY_3)
print("Generate NIST-P256 Keypair for a new certificate: {0}\n".format(list(csr_key.pkey)))

builder = csr.Builder(
	{
		'country_name': 'DE',
		'state_or_province_name': 'Bayern',
		'organization_name': 'Infineon Technologies AG',
		'common_name': 'OPTIGA(TM) Trust IoT',
	},
	csr_key
)

request = builder.build(csr_key)
csr = base64.b64encode(request.dump())
print("A new CSR {0}\n".format(csr))

```

## Testing

Tests are written using `pytest` and require this package to be installed:

```bash
$ git clone --recurse-submodules https://github.com/Infineon/python-optiga-trust
...
$ cd python-optiga-trust
$ cd tests
$ pytest
```

To run only some tests, pass a regular expression as a parameter to `tests`.

```bash
$ pytest test_rand.py
```

## Development

Existing releases can be found at https://pypi.org/project/optigatrust/.

# optigatrust

A ctypes based Python wrapper to work with the OPTIGA™ Trust security solutions.

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

 - Python 3.7+ 
 - [asn1crypto](https://github.com/wbond/asn1crypto)
 - [oscrypto](https://github.com/wbond/oscrypto)
 
## Required Hardware

  1. Either of the following:
    * OPTIGA™ Trust Personalisation Board
    * any FTDI USB-HID/I2C Converter board
    * Embedded Linux with open I2C lines; e.g. RPi3
  2. OPTIGA™ Trust X/M sample

<details>
<summary> <em> Connection details for the RPi3 and OPTIGA™ Trust X Security Shield 2Go  </em> </summary>
<img src="https://github.com/Infineon/Assets/raw/master/Pictures/optiga_trust_x_rpi3_setup.jpg"  width=60% height=%60>
</details>

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

Tests are written using `pytest` and `oscrypto` and require these packages to be installed:

```bash
$ pip3 install pytest oscrypto
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

## Add support for you own Embedded Linux

You need to build the shared library for your platform for this you need to have `cmake` and `build-essential` packages installed in your system

Then you can do the following

```bash
$ cd cd python-optiga-trust/lib/optigatrust/csrc
$ mkdir build && cd build
$ cmake ..
$ make
```

<details>
<summary> <em> Sample output </em> </summary>

```bash
pi@raspberrypi:~/git/python-optiga-trust/lib/optigatrust/csrc/build $ make
Scanning dependencies of target optigatrust-libusb-linux-armv7l
[  1%] Building C object CMakeFiles/optigatrust-libusb-linux-armv7l.dir/optiga-trust-x/optiga/crypt/optiga_crypt.c.o
[  3%] Building C object CMakeFiles/optigatrust-libusb-linux-armv7l.dir/optiga-trust-x/optiga/util/optiga_util.c.o
[  4%] Building C object CMakeFiles/optigatrust-libusb-linux-armv7l.dir/optiga-trust-x/optiga/cmd/CommandLib.c.o
[  6%] Building C object CMakeFiles/optigatrust-libusb-linux-armv7l.dir/optiga-trust-x/optiga/common/Logger.c.o
[  8%] Building C object CMakeFiles/optigatrust-libusb-linux-armv7l.dir/optiga-trust-x/optiga/common/Util.c.o
[  9%] Building C object CMakeFiles/optigatrust-libusb-linux-armv7l.dir/optiga-trust-x/optiga/comms/ifx_i2c/ifx_i2c.c.o
[ 11%] Building C object CMakeFiles/optigatrust-libusb-linux-armv7l.dir/optiga-trust-x/optiga/comms/ifx_i2c/ifx_i2c_config.c.o
[ 13%] Building C object CMakeFiles/optigatrust-libusb-linux-armv7l.dir/optiga-trust-x/optiga/comms/ifx_i2c/ifx_i2c_data_link_layer.c.o
[ 14%] Building C object CMakeFiles/optigatrust-libusb-linux-armv7l.dir/optiga-trust-x/optiga/comms/ifx_i2c/ifx_i2c_physical_layer.c.o
[ 16%] Building C object CMakeFiles/optigatrust-libusb-linux-armv7l.dir/optiga-trust-x/optiga/comms/ifx_i2c/ifx_i2c_transport_layer.c.o
[ 18%] Building C object CMakeFiles/optigatrust-libusb-linux-armv7l.dir/optiga-trust-x/optiga/dtls/AlertProtocol.c.o
[ 19%] Building C object CMakeFiles/optigatrust-libusb-linux-armv7l.dir/optiga-trust-x/optiga/dtls/DtlsFlightHandler.c.o
[ 21%] Building C object CMakeFiles/optigatrust-libusb-linux-armv7l.dir/optiga-trust-x/optiga/dtls/DtlsHandshakeProtocol.c.o
[ 22%] Building C object CMakeFiles/optigatrust-libusb-linux-armv7l.dir/optiga-trust-x/optiga/dtls/DtlsRecordLayer.c.o
[ 24%] Building C object CMakeFiles/optigatrust-libusb-linux-armv7l.dir/optiga-trust-x/optiga/dtls/DtlsTransportLayer.c.o
[ 26%] Building C object CMakeFiles/optigatrust-libusb-linux-armv7l.dir/optiga-trust-x/optiga/dtls/DtlsWindowing.c.o
[ 27%] Building C object CMakeFiles/optigatrust-libusb-linux-armv7l.dir/optiga-trust-x/optiga/dtls/HardwareCrypto.c.o
[ 29%] Building C object CMakeFiles/optigatrust-libusb-linux-armv7l.dir/optiga-trust-x/optiga/dtls/MessageLayer.c.o
[ 31%] Building C object CMakeFiles/optigatrust-libusb-linux-armv7l.dir/optiga-trust-x/optiga/dtls/OCP.c.o
[ 32%] Building C object CMakeFiles/optigatrust-libusb-linux-armv7l.dir/optiga-trust-x/optiga/dtls/OCPConfig.c.o
[ 34%] Building C object CMakeFiles/optigatrust-libusb-linux-armv7l.dir/optiga-trust-x/optiga_trust_init.c.o
[ 36%] Building C object CMakeFiles/optigatrust-libusb-linux-armv7l.dir/optiga-trust-x/pal/libusb/optiga_comms_ifx_i2c_usb.c.o
[ 37%] Building C object CMakeFiles/optigatrust-libusb-linux-armv7l.dir/optiga-trust-x/pal/libusb/pal_common.c.o
[ 39%] Building C object CMakeFiles/optigatrust-libusb-linux-armv7l.dir/optiga-trust-x/pal/libusb/pal.c.o
[ 40%] Building C object CMakeFiles/optigatrust-libusb-linux-armv7l.dir/optiga-trust-x/pal/libusb/pal_gpio.c.o
[ 42%] Building C object CMakeFiles/optigatrust-libusb-linux-armv7l.dir/optiga-trust-x/pal/libusb/pal_i2c.c.o
[ 44%] Building C object CMakeFiles/optigatrust-libusb-linux-armv7l.dir/optiga-trust-x/pal/libusb/pal_ifx_usb_config.c.o
[ 45%] Building C object CMakeFiles/optigatrust-libusb-linux-armv7l.dir/optiga-trust-x/pal/libusb/pal_os_event.c.o
[ 47%] Building C object CMakeFiles/optigatrust-libusb-linux-armv7l.dir/optiga-trust-x/pal/libusb/pal_os_lock.c.o
[ 49%] Building C object CMakeFiles/optigatrust-libusb-linux-armv7l.dir/optiga-trust-x/pal/libusb/pal_os_timer.c.o
[ 50%] Linking C shared library ../lib/liboptigatrust-libusb-linux-armv7l.so
[ 50%] Built target optigatrust-libusb-linux-armv7l
Scanning dependencies of target optigatrust-i2c-linux-armv7l
[ 52%] Building C object CMakeFiles/optigatrust-i2c-linux-armv7l.dir/optiga-trust-x/optiga/crypt/optiga_crypt.c.o
[ 54%] Building C object CMakeFiles/optigatrust-i2c-linux-armv7l.dir/optiga-trust-x/optiga/util/optiga_util.c.o
[ 55%] Building C object CMakeFiles/optigatrust-i2c-linux-armv7l.dir/optiga-trust-x/optiga/cmd/CommandLib.c.o
[ 57%] Building C object CMakeFiles/optigatrust-i2c-linux-armv7l.dir/optiga-trust-x/optiga/common/Logger.c.o
[ 59%] Building C object CMakeFiles/optigatrust-i2c-linux-armv7l.dir/optiga-trust-x/optiga/common/Util.c.o
[ 60%] Building C object CMakeFiles/optigatrust-i2c-linux-armv7l.dir/optiga-trust-x/optiga/comms/ifx_i2c/ifx_i2c.c.o
[ 62%] Building C object CMakeFiles/optigatrust-i2c-linux-armv7l.dir/optiga-trust-x/optiga/comms/ifx_i2c/ifx_i2c_config.c.o
[ 63%] Building C object CMakeFiles/optigatrust-i2c-linux-armv7l.dir/optiga-trust-x/optiga/comms/ifx_i2c/ifx_i2c_data_link_layer.c.o
[ 65%] Building C object CMakeFiles/optigatrust-i2c-linux-armv7l.dir/optiga-trust-x/optiga/comms/ifx_i2c/ifx_i2c_physical_layer.c.o
[ 67%] Building C object CMakeFiles/optigatrust-i2c-linux-armv7l.dir/optiga-trust-x/optiga/comms/ifx_i2c/ifx_i2c_transport_layer.c.o
[ 68%] Building C object CMakeFiles/optigatrust-i2c-linux-armv7l.dir/optiga-trust-x/optiga/dtls/AlertProtocol.c.o
[ 70%] Building C object CMakeFiles/optigatrust-i2c-linux-armv7l.dir/optiga-trust-x/optiga/dtls/DtlsFlightHandler.c.o
[ 72%] Building C object CMakeFiles/optigatrust-i2c-linux-armv7l.dir/optiga-trust-x/optiga/dtls/DtlsHandshakeProtocol.c.o
[ 73%] Building C object CMakeFiles/optigatrust-i2c-linux-armv7l.dir/optiga-trust-x/optiga/dtls/DtlsRecordLayer.c.o
[ 75%] Building C object CMakeFiles/optigatrust-i2c-linux-armv7l.dir/optiga-trust-x/optiga/dtls/DtlsTransportLayer.c.o
[ 77%] Building C object CMakeFiles/optigatrust-i2c-linux-armv7l.dir/optiga-trust-x/optiga/dtls/DtlsWindowing.c.o
[ 78%] Building C object CMakeFiles/optigatrust-i2c-linux-armv7l.dir/optiga-trust-x/optiga/dtls/HardwareCrypto.c.o
[ 80%] Building C object CMakeFiles/optigatrust-i2c-linux-armv7l.dir/optiga-trust-x/optiga/dtls/MessageLayer.c.o
[ 81%] Building C object CMakeFiles/optigatrust-i2c-linux-armv7l.dir/optiga-trust-x/optiga/dtls/OCP.c.o
[ 83%] Building C object CMakeFiles/optigatrust-i2c-linux-armv7l.dir/optiga-trust-x/optiga/dtls/OCPConfig.c.o
[ 85%] Building C object CMakeFiles/optigatrust-i2c-linux-armv7l.dir/optiga-trust-x/optiga_trust_init.c.o
[ 86%] Building C object CMakeFiles/optigatrust-i2c-linux-armv7l.dir/optiga-trust-x/optiga/comms/optiga_comms.c.o
[ 88%] Building C object CMakeFiles/optigatrust-i2c-linux-armv7l.dir/optiga-trust-x/pal/linux/pal.c.o
[ 90%] Building C object CMakeFiles/optigatrust-i2c-linux-armv7l.dir/optiga-trust-x/pal/linux/pal_gpio.c.o
[ 91%] Building C object CMakeFiles/optigatrust-i2c-linux-armv7l.dir/optiga-trust-x/pal/linux/pal_i2c.c.o
[ 93%] Building C object CMakeFiles/optigatrust-i2c-linux-armv7l.dir/optiga-trust-x/pal/linux/target/rpi3/pal_ifx_i2c_config.c.o
[ 95%] Building C object CMakeFiles/optigatrust-i2c-linux-armv7l.dir/optiga-trust-x/pal/linux/pal_os_event.c.o
[ 96%] Building C object CMakeFiles/optigatrust-i2c-linux-armv7l.dir/optiga-trust-x/pal/linux/pal_os_lock.c.o
[ 98%] Building C object CMakeFiles/optigatrust-i2c-linux-armv7l.dir/optiga-trust-x/pal/linux/pal_os_timer.c.o
[100%] Linking C shared library ../lib/liboptigatrust-i2c-linux-armv7l.so
[100%] Built target optigatrust-i2c-linux-armv7l
```
</details>

## Development

Existing releases can be found at https://pypi.org/project/optigatrust/.

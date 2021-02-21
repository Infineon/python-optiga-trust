# optigatrust Python library

A ctypes based Python wrapper to work with the OPTIGA™ Trust security solutions.

[![PyPI](https://img.shields.io/pypi/v/optigatrust.svg)](https://pypi.org/project/optigatrust/)

## Features

*optigatrust* is a library which helps to manage the OPTIGA Trust family of security solutions
Find more about these products here:
* [OPTIGA™ Trust M](https://github.com/Infineon/optiga-trust-m)
* [OPTIGA™ Trust Charge](https://github.com/Infineon/optiga-trust-charge)
* [OPTIGA™ Trust X](https://github.com/Infineon/optiga-trust-x)

[**Documentation**](https://infineon.github.io/python-optiga-trust)
 
## Required Hardware

* Any of the following
    - OPTIGA™ Trust [M](https://www.infineon.com/cms/en/product/evaluation-boards/optiga-trust-m-eval-kit/)/[Charge](https://www.infineon.com/cms/en/product/evaluation-boards/optiga-trust-ch-eval-kit/) Evaluation Kit
    - OPTIGA™ Trust Personalisation Board (SP005405452), or any FTDI USB-HID/I2C Converter board
    - Raspberry Pi + [Shield2Go RPi Adapter](https://www.infineon.com/cms/en/product/evaluation-boards/s2go-adapter-rasp-pi-iot/)
* OPTIGA™ Trust X/M/Charge sample or a Security Shield2Go

## Installation

```bash
$ pip install optigatrust
```

### Examples

```python
import optigatrust as optiga
from optigatrust import objects, crypto
import json

chip = optiga.Chip()
chip.current_limit = 15

ecc_key_0 = objects.ECCKey(0xe0f0) 

print('Pretty metadata: {0}'.format(json.dumps(ecc_key_0.meta, indent=4)))

public_key, private_key = crypto.generate_pair(ecc_key_0, curve='secp256r1', export=True)

print('Pulic Key = {0}, Privat key = {1}'.format(public_key, private_key))

```

## License

*optigatrust* is licensed under the terms of the MIT license. See the
[LICENSE](LICENSE) file for the exact license text.

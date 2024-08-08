<div align="center">

<picture>
<img alt="Infineon logo" src="docs/images/infineon_logo_color.png" width="25%">
</picture>

###

[![PyPI](https://img.shields.io/pypi/v/optigatrust.svg)](https://pypi.org/project/optigatrust/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Python version](https://img.shields.io/badge/Python-3-green?logo=python)](https://www.python.org/)

# Infineon OPTIGA™ Trust M Host Library for Python

A [ctypes](https://docs.python.org/3/library/ctypes.html) based Python wrapper for the [OPTIGA™ Trust M Host Library for C](https://github.com/Infineon/optiga-trust-m).

</div>

## Features

This Python module is a wrapper for the [OPTIGA™ Trust M Host Library for C](https://github.com/Infineon/optiga-trust-m) and allows the communication with OPTIGA™ Trust M devices.

Please see the [OPTIGA™ Trust M overview repository](https://github.com/optiga-trust-m-overview) for more information on our OPTIGA™ Trust M product family.

## Required hardware

* Any of the following
    - PSoC™ 6 Kit in [Provisioning Mode](https://github.com/Infineon/mtb-example-optiga-data-management) + [OPTIGA™ Trust Adapter](https://www.infineon.com/cms/en/product/evaluation-boards/optiga-trust-adapter)
    - OPTIGA™ Trust [M](https://www.infineon.com/cms/en/product/evaluation-boards/optiga-trust-m-eval-kit/)/[Charge](https://www.infineon.com/cms/en/product/evaluation-boards/optiga-trust-ch-eval-kit/) Evaluation Kit
    - OPTIGA™ Trust Personalisation Board (SP005405452), or any FTDI USB-HID/I2C Converter board
    - Raspberry Pi + [Shield2Go RPi Adapter](https://www.infineon.com/cms/en/product/evaluation-boards/s2go-adapter-rasp-pi-iot/)
    - Raspberry Pi + [Pi 4 Click Shield](https://www.mikroe.com/pi-4-click-shield)
    
* OPTIGA™ Trust X/M/Charge sample, a [Security Shield2Go](https://www.infineon.com/cms/en/product/evaluation-boards/s2go-security-optiga-m/) or a mikroBUS compatible OPTIGA™ Trust M Shield.

## Installation from pip

To install this Python module from pip, run the following command

```bash
$ python -m pip install optigatrust
```

## Building from sources

### Building the OPTIGA™ Trust Host Library for C as library

Please follow the steps in [extras/optiga-trust-m/README.md](extras/optiga-trust-m/README.md) for building the OPTIGA™ Trust Host Library for C as library.

### Installing the optigatrust Python module from source

Please follow the steps in [INSTALL.md](INSTALL.md) for installing the `optigatrust` Python module from source.

## Project structure

```bash
python-optiga-trust
├── docs
├── examples
├── extras
│   └── optiga-trust-m
├── src
│   └── optigatrust
└── tests
```

| Folder                | Content                                       |
| --------------------- | --------------------------------------------- |
| docs                  | GitHub.io documentation                       |
| examples              | Example Python scripts                        |
| extras/optiga-trust-m | OPTIGA™ Trust Host Library for C as submodule |
| src/optigatrust       | Python module optigatrust                     |
| tests                 | Tests for the Python module optigatrust       |

## Licensing
   
Please see our [LICENSE](LICENSE) for copyright and license information.
   
This project follows the REUSE approach, so copyright and licensing information is available for every file (including third party components) either in the file header, an individual *.license file or the .reuse/dep5 file. All licenses can be found in the [LICENSES](LICENSES) folder.

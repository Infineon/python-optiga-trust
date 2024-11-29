[![PyPI](https://img.shields.io/pypi/v/optigatrust.svg)](https://pypi.org/project/optigatrust/)

# Infineon OPTIGA™ Trust M Host Library for Python

A [ctypes](https://docs.python.org/3/library/ctypes.html) based Python wrapper for the [OPTIGA™ Trust M Host Library for C](https://github.com/Infineon/optiga-trust-m).

The source code of this Python package is available in the [OPTIGA™ Trust M Host Library for Python](https://github.com/Infineon/python-optiga-trust) GitHub repository.

## Features

This Python module is a wrapper for the [OPTIGA™ Trust M Host Library for C](https://github.com/Infineon/optiga-trust-m) and allows the communication with OPTIGA™ Trust M devices.

Please see the [OPTIGA™ Trust M Overview Repository](https://github.com/Infineon/optiga-trust-m-overview) for more information on our OPTIGA™ Trust M product family.
 
## Installation

```bash
$ python -m pip install optigatrust
```

### libusb: Allow access to USB device (USB-to-UART-interface)

If you want to use the `optigatrust` Python package with libusb and a USB-to-UART-interface from user space, the access has to be permitted with a udev rule.

#### Automatic installation of the udev rule (root permission needed)

When the package installation is performed with root permissions, it will install the udev rule for the OPTIGA™ Trust M Perso2Go board automatically.

```bash
$ sudo python -m pip install optigatrust
```

#### Manual installation of the udev rule

For manually installing the udev rule, please consult the README.md in our [OPTIGA™ Trust M Host Library for Python](https://github.com/Infineon/python-optiga-trust) GitHub repository.

## Documentation

The documentation of this Python module can be found here:
* [Online documentation on GitHub.io](https://infineon.github.io/python-optiga-trust)
* [Source code documentation on GitHub](https://github.com/Infineon/python-optiga-trust)

## OPTIGA™ Trust M product information

Please find more information about the OPTIGA™ Trust M product family on the [OPTIGA™ Trust M Overview Repository](https://github.com/Infineon/optiga-trust-m-overview).

## Source code and examples

Please find the source code and examples for this Python module on the [OPTIGA™ Trust M Host Library for Python](https://github.com/Infineon/python-optiga-trust) GitHub repository.

## Licensing

This project is published under the MIT license and with copyright of Infineon Technologies AG. For more details, see the [OPTIGA™ Trust M Host Library for Python](https://github.com/Infineon/python-optiga-trust) GitHub repository.
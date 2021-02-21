.. header::

   GUIDELINE

.. footer::

   Created 2021-01-18, 1.0.1

Welcome to ``infineon/python-optiga-trust``
===========================================

``optigatrust`` python module is a ctypes based wrapper to work with the OPTIGA™ Trust security solutions.

Dependencies
^^^^^^^^^^^^

 - Python 3.7+
 - CSR and X509 Handling - asn1crypto_
 - For tests - oscrypto_, cryptography_
 - XML handling in export module jinja2_
 - Keys wrap/unwrap operations cryptography_

How does it work
^^^^^^^^^^^^^^^^

This python module comes with a set of shared libraries, which are precompiled for different communication interfaces.
The shared libraries are fully based on the `official framework`_. This module doesn't simply implement bindings for the library, but add many more things on top. See Documentation.
In the end the module supports the following combinations

==============  ===========  =========
Interface/OS    **Windows**  **Linux**
--------------  -----------  ---------
**EvalKit**       Yes           No
**PersoBoard**    Yes           Yes
**Raw I2C**       No            Yes
==============  ===========  =========

Required Hardware
^^^^^^^^^^^^^^^^^

  - Any of the following
     - OPTIGA™ Trust M1/M3/Charge EvalKit. See :doc:`Provisioning mode <prov_mode>` for details.
     - OPTIGA™ Trust Personalisation Board, or any FTDI USB-HID/I2C Converter board
     - Raspberry Pi + Shield2Go RPi Adapter_
  - OPTIGA™ Trust X/M/Charge sample or a Security Shield2Go

Note: If you use any of the embedded Linux as a Host, please don't forget to enable i2c support in your kernel (RPi3: via `raspi-config` command), as well as add your user to the gpio group (RPi3: via `sudo adduser pi gpio`)
`RaspberryPi3 Connection Example`_.

Installation
^^^^^^^^^^^^

::

	$ pip install optigatrust


Testing
^^^^^^^

Tests are written using `pytest` and `oscrypto` and require these packages to be installed: ::

	$ pip3 install pytest oscrypto
	$ git clone --recurse-submodules https://github.com/Infineon/python-optiga-trust
	...
	$ cd python-optiga-trust
	$ cd tests
	$ pytest


To run only some tests, pass a regular expression as a parameter to `tests`. ::

	$ pytest test_rand.py




.. toctree::
   :maxdepth: 3
   :caption: Contents
   :numbered:

.. raw:: latex

   % Skip the contents chapter
   \refstepcounter{chapter}

.. toctree::
   :maxdepth: 3
   :caption: Contents
   :numbered:

   chip
   metadata
   crypto
   csr
   port
   linux_support
   prov_mode
   copyright


.. _asn1crypto: https://github.com/wbond/asn1crypto
.. _oscrypto: https://github.com/wbond/oscrypto
.. _jinja2: https://jinja.palletsprojects.com/en/2.11.x/
.. _cryptography: https://github.com/pyca/cryptography
.. _RaspberryPi3 Connection Example: https://github.com/Infineon/Assets/raw/master/Pictures/optiga_trust_x_rpi3_setup.jpg
.. _Adapter: https://www.infineon.com/cms/en/product/evaluation-boards/s2go-adapter-rasp-pi-iot/
.. _official framework: https://github.com/Infineon/optiga-trust-m/
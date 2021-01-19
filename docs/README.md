# optigatrust Documentation

*optigatrust* is a library which helps to manage the OPTIGA Trust family of security solutions
Find more about these products here:
* [OPTIGA™ Trust M](https://github.com/Infineon/optiga-trust-m)
* [OPTIGA™ Trust Charge](https://github.com/Infineon/optiga-trust-charge)
* [OPTIGA™ Trust X](https://github.com/Infineon/optiga-trust-x)

| Submodule                                | Functionality                                                                                 |
| ---------------------------------------- | --------------------------------------------------------------------------------------------- |
| [`optigatrust.core`](core.md)   | Chip initialiastion, Random, work with Metadata 
| [`optigatrust.symmetric`](symmetric.md)     | AES encryption/decryption, HMAC                                                  |
| [`optigatrust.asymmetric`](asymmetric.md)   | RSA, ECDSA and EC-key signing, verification, and key pair generation, RSA encryption                                  |
| [`optigatrust.kdf`](kdf.md)                 | HKDF, TLS PRF 1.2 key derivation functions                                           |
| [`optigatrust.cert`](cert.md)               | Certificate, public key and private key loading, parsing                    |                                           |
| [`optigatrust.export`](export.md)               | Dump chip's configuration in json or OPTIGA Trust Configurator supported formats                                       |

## Concept

This library attempts to present work with the chip natural to the chip manner, using the ['Object'](https://github.com/Infineon/python-optiga-trust/blob/3c17eb223d31a0a2a017e99fd5e2d3249f011f59/optigatrust/core.py#L730) abstraction.
Objects on the chip might be of several types:
* Certificate Object
* Trust Anchors Object
* Key Object
* Application Data Object
* Service Object

A sample layout of the Objects can be found below (for OPTIGA™ Trust M3)

![](https://github.com/Infineon/Assets/blob/master/Pictures/trustm_keystore_dataobjects_v04.png)


# SPDX-FileCopyrightText: 2024 Infineon Technologies AG
# SPDX-License-Identifier: MIT

"""ECC Key Generation Example.

This example shows how to create an ECC key pair using OPTIGA™ Trust M.

The key pair is generated in data object 0xE0F3 using the secp256r1 curve.
"""

# Uncomment to use the local version (source) of this library instead of the pip package
# import sys, os
# sys.path.append(os.path.join(os.path.dirname(__file__), ".." , "src"))

import json

import optigatrust as optiga
from optigatrust import objects, crypto, util


chip = optiga.Chip()
chip.current_limit = 10

ecc_key_0 = objects.ECCKey(0xE0F3)

print("Pretty metadata: {0}".format(json.dumps(ecc_key_0.meta, indent=4)))

public_key, private_key = crypto.generate_pair(ecc_key_0, curve="secp256r1", export=True)

print("Private key:\n{0}".format(util.binary_to_hex(private_key)))
print("Public key:\n{0}".format(util.binary_to_hex(public_key)))

# SPDX-FileCopyrightText: 2024 Infineon Technologies AG
# SPDX-License-Identifier: MIT

# Uncomment to use the local version (source) of this library instead of the pip package
# import sys, os
# sys.path.append(os.path.join(os.path.dirname(__file__), ".." , "src"))

import json, logging

import optigatrust as optiga
from optigatrust import objects, crypto, util

logger = util.Logger(name=__name__, level=logging.INFO)

chip = optiga.Chip()
chip.current_limit = 10

ecc_key_0 = objects.ECCKey(0xE0F0)

logger.info("Pretty metadata: {0}".format(json.dumps(ecc_key_0.meta, indent=4)))

public_key, private_key = crypto.generate_pair(
    ecc_key_0, curve="secp256r1", export=True
)

logger.info("Private key:\n{0}".format(util.binary_to_hex(private_key)))
logger.info("Public key:\n{0}".format(util.binary_to_hex(public_key)))
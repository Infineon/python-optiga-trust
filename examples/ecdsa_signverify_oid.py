# SPDX-FileCopyrightText: 2024 Infineon Technologies AG
# SPDX-License-Identifier: MIT

# Uncomment to use the local version (source) of this library instead of the pip package
import sys, os
sys.path.append(os.path.join(os.path.dirname(__file__), ".." , "src"))

import logging

from optigatrust import objects, crypto, util

logger = util.Logger(name=__name__, level=logging.INFO)

hashname = "sha256"
data = b"Test String to sign"
oid_private_key = 0xE0F0
oid_certificate = 0xE0E3

key_object = objects.ECCKey(oid_private_key)

# Create signature via OPTIGA Trust M
s = crypto.ecdsa_sign_with_hash(key_object, data, hashname)

logger.info("Signature:\n{0}".format(util.binary_to_hex(s.signature)))

# Take the certificate from slot E0E0 and write it to slot E0E3
cert_object = objects.X509(0xE0E0)
cert_object_new = objects.X509(oid_certificate)
cert_object_new.write(cert_object.der)

# Verify signature via OPTIGA Trust M using public key from host
signature_is_valid = crypto.ecdsa_verify_data_oid(s.signature, data, hashname, oid_certificate)
if signature_is_valid:
    logger.info("Signature validation successful!")

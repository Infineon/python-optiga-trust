# SPDX-FileCopyrightText: 2024 Infineon Technologies AG
# SPDX-License-Identifier: MIT

"""ECDSA Signature Creation and Verification

This example shows how to create an ECDSA signature using a private key generated in the OPTIGA™ Trust M device. This
allows to export the respective public key, which is then used to verify the ECDSA signature in the OPTIGA™ Trust M by
handing over the exported public key from host.
"""

# Uncomment to use the local version (source) of this library instead of the pip package
# import sys, os
# sys.path.append(os.path.join(os.path.dirname(__file__), ".." , "src"))

from optigatrust import objects, crypto, util

curve = "secp256r1"
hashname = "sha256"

data = b"Test String to sign"
key_object = objects.ECCKey(0xE100)

# Create key pair in OPTIGA™ Trust M
public_key, _ = crypto.generate_pair(key_object, curve=curve)

hash = crypto.calculate_hash(hashname, data)

# Create signature via OPTIGA™ Trust M
s = crypto.ecdsa_sign_with_hash(key_object, data, hashname)

print("Public key:\n{0}".format(util.binary_to_hex(public_key)))
print("Hash:\n{0}".format(util.binary_to_hex(hash)))
print("Signature:\n{0}".format(util.binary_to_hex(s.signature)))

# Verify signature via OPTIGA™ Trust M using public key from host
signature_is_valid = crypto.ecdsa_verify_data_pk_host(
    s.signature, data, hashname, public_key, curve
)
if signature_is_valid:
    print("Signature validation successful!")
else:
    print("Signature validation failed!")

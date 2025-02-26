# SPDX-FileCopyrightText: 2024 Infineon Technologies AG
# SPDX-License-Identifier: MIT

"""Verify ECSA Signature with OPTIGA™ Trust M

This example shows verify an ECDSA signature in the OPTIGA™ Trust M by handing over the exported public key from host.
"""

# Uncomment to use the local version (source) of this library instead of the pip package
# import sys, os
# sys.path.append(os.path.join(os.path.dirname(__file__), ".." , "src"))

from optigatrust import crypto, util

# Own test data with R/S padding changed
curve = "secp521r1"
hash = bytes.fromhex("c1dc882728fb782d7b3d0dd2b8d4115abd35d11c6686370a91f6dc896a228507")
# Remove everything before 03.. from ASN1 public key
public_key = bytes.fromhex(
    "0381860004006bc78005df34b4c5409d45e402128e2a44ac01848548627a7a930261e82404be114f0d89a0453ae805bacd1e6d43d667b7f2521adfe47ea7958eb68411f6d5555d00ece80ede9ff4813635b07cf26910c0e48fbd2eb9f7905bba4e7202267868902940f8dc2c15d221cf9d71823b9756b5cf1adec37899792fe33d057e62aa6cc9888c"
)
# Remove everything before 02... from ASN1 signature
signature = bytes.fromhex(
    "024176f426e19588582eb56805feaffa1f62ca9dcfd323adfc2ddfc52758f3af847a5dfd9f0d0a8585448366e775f9bfeaf2bf5af3e1a80362e32134d9ad5c87819ea702412a5a6555e0e4daaeb8c5ef762360d1e0f89fb4cc9108a7c4faf5bbb790b3e255666454810e047aa87ac501a05d8bee4fe93e8b607cc51a6109d889cd19e96b42f4"
)

print("Public key:\n{0}".format(util.binary_to_hex(public_key)))
print("Hash:\n{0}".format(util.binary_to_hex(hash)))
print("Signature:\n{0}".format(util.binary_to_hex(signature)))

# Verify signature via OPTIGA™ Trust M
signature_is_valid = crypto.ecdsa_verfiy_hash_pk_host(signature, hash, public_key, curve)
if signature_is_valid:
    print("Signature validation successful!")
else:
    print("Signature validation failed!")

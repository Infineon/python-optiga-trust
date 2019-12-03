# ============================================================================
# The MIT License
#
# Copyright (c) 2018 Infineon Technologies AG
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE
# ============================================================================
from collections import namedtuple
from enum import IntFlag

__all__ = ['Rng', 'Curves', 'str2curve', 'KeyUsage', 'ObjectId', 'KeyId', 'KeyUsage', 'UID']


class Rng(IntFlag):
	# OPTIGA Trust RNG Enumeration
	TRNG = 0
	DRNG = 1


class Curves(IntFlag):
	NIST_P_256 = 3
	NIST_P_384 = 4


def str2curve(curve_str, return_value=False):
	if curve_str == 'secp256r1':
		c = Curves.NIST_P_256
	elif curve_str == 'secp384r1':
		c = Curves.NIST_P_384
	else:
		raise ValueError('Curve not supported use either nistp256r1 or nistp384r1')

	if return_value:
		return c.value
	else:
		return c


class KeyUsage(IntFlag):
	# This enables the private key for the signature generation as part of authentication commands
	AUTHENTICATION = 0x01
	# This enables the private key for encrypt and decrypt
	ENCRYPTION = 0x02
	# This enables the private key for the signature generation
	SIGN = 0x10
	# This enables the private key for key agreement (e.g. ecdh operations)
	KEY_AGREEMENT = 0x20


class ObjectId(IntFlag):
	# Default Infineon Certificate Slot
	IFX_CERT = 0xE0E0
	# User defined certificate Slot 1
	USER_CERT_1 = 0xE0E1
	# User defined certificate Slot 2
	USER_CERT_2 = 0xE0E2
	# User defined certificate Slot 3
	USER_CERT_3 = 0xE0E3
	# An Object OID to store a first Trust Anchor
	TRUST_ANCHOR_1 = 0xE0E8
	# An Object OID to store a second Trust Anchor
	TRUST_ANCHOR_2 = 0xE0EF
	# An Object OIDs to store arbitrary data type 1 (Refer to the solution reference manual).
	# 100 bytes each
	DATA_TYPE1_0 = 0xF1D0
	DATA_TYPE1_1 = 0xF1D1
	DATA_TYPE1_2 = 0xF1D2
	DATA_TYPE1_3 = 0xF1D3
	DATA_TYPE1_4 = 0xF1D4
	DATA_TYPE1_5 = 0xF1D5
	DATA_TYPE1_6 = 0xF1D6
	DATA_TYPE1_7 = 0xF1D7
	DATA_TYPE1_8 = 0xF1D8
	DATA_TYPE1_9 = 0xF1D9
	DATA_TYPE1_A = 0xF1DA
	DATA_TYPE1_B = 0xF1DB
	DATA_TYPE1_C = 0xF1DC
	DATA_TYPE1_D = 0xF1DD
	DATA_TYPE1_E = 0xF1DE
	# An Object OIDs to store arbitrary data type 2 (Refer to the solution reference manual)
	# 1500 bytes each
	DATA_TYPE2_0 = 0xF1E0
	DATA_TYPE2_1 = 0xF1E1

	COPROCESSOR_UID = 0xE0C2


class KeyId(IntFlag):
	# Key from key store
	ECC_KEY_E0E0 = 0xE0F0
	# Key from key store
	ECC_KEY_E0F1 = 0xE0F1
	# Key from key store
	ECC_KEY_E0F2 = 0xE0F2
	# Key from key store
	ECC_KEY_E0F3 = 0xE0F3
	# Key from key store
	RSA_KEY_E0FC = 0xE0FC
	# Key from key store
	RSA_KEY_E0FD = 0xE0FD

	# Key from Session context id 1
	SESSION_ID_1 = 0xE100
	# Key from Session context id 2
	SESSION_ID_2 = 0xE101
	# Key from Session context id 3
	SESSION_ID_3 = 0xE102
	# Key from Session context id 4
	SESSION_ID_4 = 0xE103


def has_value(cls, value):
	return any(value == item.value for item in cls)


UID = namedtuple("UID", "cim_id platform_id model_id rommask_id chip_type batch_num x_coord y_coord fw_id fw_build")

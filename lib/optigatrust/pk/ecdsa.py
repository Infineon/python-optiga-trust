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

import hashlib
import warnings
from ctypes import *

from optigatrust.pk import EccKey, EcdsaSignature
from optigatrust.util import chip


def sign(ecckey, data):
	"""
	This function signs given data based on the provided EccKey object

	:param ecckey:
		a valid EccKey object. Use ecc.generate_keypair() for this

	:param data:
		Data to sign, the data will be hashed based on the used curve. If secp256r1 then sha256, otherwise sha384

	:raises:
		TypeError - when any of the parameters are of the wrong type
		OSError - when an error is returned by the chip initialisation library

	:return:
		EcdsaSignature object or None
	"""
	api = chip.init()

	if not isinstance(data, bytes) and not isinstance(data, bytearray):
		if isinstance(data, str):
			_d = bytes(data.encode())
			warnings.warn("data will be converted to bytes type before signing")
		else:
			raise TypeError('Data to sign should be either bytes or str type, you gave {0}'.format(type(data)))
	else:
		_d = data

	if not isinstance(ecckey, EccKey):
		raise TypeError('Key ID should be selected of class KeyId')

	api.exp_optiga_crypt_ecdsa_sign.argtypes = POINTER(c_ubyte), c_ubyte, c_ushort, POINTER(c_ubyte), POINTER(c_ubyte)
	api.exp_optiga_crypt_ecdsa_sign.restype = c_int

	if ecckey.curve == 'secp256r1':
		digest = (c_ubyte * 32)(*hashlib.sha256(_d).digest())
		s = (c_ubyte * (64 + 6))()
		hash_algorithm = 'sha256'
	elif ecckey.curve == 'secp384r1':
		digest = (c_ubyte * 48)(*hashlib.sha384(_d).digest())
		s = (c_ubyte * (96 + 6))()
		hash_algorithm = 'sha384'
	c_slen = c_ubyte(len(s))

	ret = api.exp_optiga_crypt_ecdsa_sign(digest, len(digest), ecckey.keyid.value, s, byref(c_slen))

	if ret == 0:
		signature = (c_ubyte * (c_slen.value + 2))()
		signature[0] = 0x30
		signature[1] = c_slen.value
		memmove(addressof(signature) + 2, s, c_slen.value)

		return EcdsaSignature(hash_algorithm, ecckey.keyid, bytes(signature))
	else:
		warnings.warn("Failed to sign a data, return a NoneType")
		return None

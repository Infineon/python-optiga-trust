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
from optigatrust.util import Curves, chip


def sign(ecckey, d, hash_algorithm='sha256'):
	api = chip.init()

	if not isinstance(d, bytes):
		_d = bytes(d)
		warnings.warn("data will be converted to bytes type before signing")
	else:
		_d = d

	if not isinstance(ecckey, EccKey):
		raise Exception('Key ID should be selected of class KeyId')

	api.optiga_crypt_ecdsa_sign.argtypes = POINTER(c_ubyte), c_ubyte, c_ushort, POINTER(c_ubyte), POINTER(c_ubyte)
	api.optiga_crypt_ecdsa_sign.restype = c_int

	if ecckey.curve == Curves.NIST_P_256:
		digest = (c_ubyte * 32)(*hashlib.sha256(_d).digest())
		s = (c_ubyte * (64 + 6))()
	elif ecckey.curve == Curves.NIST_P_384:
		digest = (c_ubyte * 48)(*hashlib.sha384(_d).digest())
		s = (c_ubyte * (96 + 6))()

	c_slen = c_ubyte(len(s))

	ret = api.optiga_crypt_ecdsa_sign(digest, len(digest), ecckey.keyid.value, s, byref(c_slen))

	if ret == 0:
		signature = (c_ubyte * (c_slen.value + 3))()
		signature[0] = c_ubyte(0x30)
		signature[1] = c_ubyte(0x00)
		signature[2] = c_ubyte(c_slen.value)
		memmove(addressof(signature) + 3, s, c_slen.value)

		return EcdsaSignature(hash_algorithm, ecckey.curve, ecckey.keyid, bytes(signature))
	else:
		return None

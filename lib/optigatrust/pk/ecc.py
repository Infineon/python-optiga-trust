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
from ctypes import *
import warnings

from optigatrust.pk import EccKey
from optigatrust.util import chip
from optigatrust.util.types import KeyId, KeyUsage, str2curve


def generate_keypair(curve='secp256r1', keyid=KeyId.ECC_KEY_E0F1):
	"""
	This function generates an ECC keypair, the private part is stored on the chip based on the provided slot

	:param curve:
		Curve name, should be either secp256r1 or secp384r1

	:param keyid:
		A Private Key Slot object ID. The value should be within the KeyId Enumeration

	:raises
		TypeError - when any of the parameters are of the wrong type
		OSError - when an error is returned by the chip initialisation library

	:return:
		EccKey object or None
	"""
	_bytes = None
	api = chip.init()

	c = str2curve(curve, return_value=True)

	if not isinstance(keyid, KeyId):
		raise TypeError('Key ID should be selected of class KeyId')

	api.exp_optiga_crypt_ecc_generate_keypair.argtypes = c_int, c_ubyte, c_bool, c_void_p, POINTER(c_ubyte), POINTER(c_ushort)
	api.exp_optiga_crypt_ecc_generate_keypair.restype = c_int

	c_keyusage = c_ubyte(KeyUsage.KEY_AGREEMENT.value | KeyUsage.AUTHENTICATION.value)
	c_keyid = c_ushort(keyid.value)
	p = (c_ubyte * 100)()
	c_plen = c_ushort(len(p))

	ret = api.exp_optiga_crypt_ecc_generate_keypair(c, c_keyusage, 0,  byref(c_keyid), p, byref(c_plen))

	pubkey = (c_ubyte * c_plen.value)()
	memmove(pubkey, p, c_plen.value)

	if ret == 0:
		return EccKey(pkey=bytes(pubkey), keyid=keyid, curve=curve)
	else:
		warnings.warn("Failed to generate an ECC keypair, return a NoneType")
		return None

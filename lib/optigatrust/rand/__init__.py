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

from optigatrust.util import chip
from optigatrust.util.types import Rng

__all__ = ['get_random_bytes']


def get_random_bytes(n, trng=True):
	"""
	This function generates a random number

	:param n:
		how much randomness to generate. Valid values are from 8 to 256

	:param trng:
		If True the a True Random Generator will be used, otherwise Deterministic Random Number Generator

	:raises:
		TypeError - when any of the parameters are of the wrong type
		OSError - when an error is returned by the chip initialisation library

	:return:
		Bytes object with randomness
	"""
	api = chip.init()

	api.exp_optiga_crypt_random.argtypes = c_byte, POINTER(c_ubyte), c_ushort
	api.exp_optiga_crypt_random.restype = c_int
	p = (c_ubyte * n)()
	
	if trng is True:
		ret = api.exp_optiga_crypt_random(Rng.TRNG.value, p, len(p))
	else:
		ret = api.exp_optiga_crypt_random(Rng.DRNG.value, p, len(p))
		
	if ret == 0:
		return bytes(p)
	else:
		return bytes(0)
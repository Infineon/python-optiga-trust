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


def read(keyid, offset=0):
	"""
	This function either deinitialises the communication channel between the chip and the application

	:param None:
	:return:
		a CDLL Instance
	"""
	_bytes = None
	api = chip.init()

	if offset > 1700:
		raise ValueError("offset should be less than the limit of 1700 bytes")

	api.optiga_util_read_data.argtypes = c_ushort, c_ushort, POINTER(c_ubyte), POINTER(c_ushort)
	api.optiga_util_read_data.restype = c_int

	d = (c_ubyte * 1700)()
	c_dlen = c_ushort(len(d))

	ret = api.optiga_util_read_data(keyid, offset, d, byref(c_dlen))

	data = (c_ubyte * c_dlen.value)()
	memmove(data, d, sizeof(d))

	if ret == 0:
		_bytes = bytes(data)

	return data


def write(data, keyid, offset=0):
	api = chip.init()

	if not isinstance(data, bytes):
		raise TypeError("data should be bytes type")

	if len(data) > 1700:
		raise ValueError("length of data exceeds the limit of 1700")

	if offset > 1700:
		raise ValueError("offset should be less than the limit of 1700 bytes")

	api.optiga_util_write_data.argtypes = c_ushort, c_ubyte, c_ushort, POINTER(c_ubyte), c_ushort
	api.optiga_util_write_data.restype = c_int

	ret = api.optiga_util_write_data(keyid, 0x40, offset, data, len(data))

	return ret

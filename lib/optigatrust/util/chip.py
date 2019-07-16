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
import os
import platform
import sys
from ctypes import *

from optigatrust.util.types import UID


__all__ = ['init', 'deinit', 'fwversion', 'uid']

optiga_initialised = False
optiga_lib_handler = None


def _get_arch_os():
	platforms = {
		'linux': 'linux',
		'linux1': 'linux',
		'linux2': 'linux',
		'darwin': 'osx',
		'cygwin': 'win',
		'msys': 'win',
		'win32': 'win',
	}

	if sys.platform not in platforms:
		return sys.platform
		
	_,_,_,_, arch,_ = platform.uname()
	
	return arch, platforms[sys.platform]


def _get_lib_name(interface='libusb'):
	arch, os = _get_arch_os()

	return 'liboptigatrust-{interface}-{os}-{arch}.so'.format(interface=interface, os=os, arch=arch)


def _load_lib(interface):
	libname = _get_lib_name(interface)
	
	old_path = os.getcwd()
	
	curr_path = os.path.abspath(os.path.dirname(__file__) + "/../csrc/lib/")

	os.chdir(curr_path)
	if os.path.exists(os.path.join(curr_path, libname)):
		api = cdll.LoadLibrary(os.path.join(curr_path, libname))
	else:
		api = None
		os.chdir(old_path)
		raise OSError('Unable to find library in {}'.format(curr_path))
	api.optiga_init.restype = c_int
	ret = api.optiga_init()
	if ret != 0:
		os.chdir(old_path)
		raise OSError('Failed to initialise the chip. Exit.')
		
	os.chdir(old_path)
	return api


def init(init_trustm=False):
	"""
	This function either initialises non-initialised communication channel between the chip and the application, or
	returns an existing communication

	:param None:

	:raises:
		OSError: If some problems occured during the initialisation of the library or the chip

	:return:
		a CDLL Instance
	"""
	global optiga_initialised
	global optiga_lib_handler
	
	if not optiga_initialised and optiga_lib_handler is None:
	
		try:
			"""
			Here we try to probe which interface is actually in use, might be either libusb or i2c
			We suppress stderr output of the libusb interface in case it's npot connected to not confuse
			a user
			"""
			api = _load_lib('libusb')
			print('Loaded: {0}'.format(_get_lib_name('libusb')))
		except OSError:
			api = _load_lib('i2c')
			print('Loaded: {0}'.format(_get_lib_name('i2c')))
		
		
		optiga_initialised = True
		optiga_lib_handler = api

	return optiga_lib_handler


def deinit():
	"""
	This function either deinitialises the communication channel between the chip and the application

	:param None:

	:return:
		a CDLL Instance
	"""
	global optiga_initialised
	global optiga_lib_handler

	optiga_initialised = False
	optiga_lib_handler = None


def fwversion():
	pass


def uid():
	return UID()
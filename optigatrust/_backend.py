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
import os
import platform
import sys
from re import match


_optiga_cddl = None


__all__ = [
    'get_handler',
    'set_com_port_config'
]


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

    targets = {
        '32bit': 'i686',
        '64bit': 'amd64'
    }

    if sys.platform not in platforms:
        return sys.platform

    _, _, _, _, arch, _ = platform.uname()

    if platforms[sys.platform] == 'win':
        arch = targets[platform.architecture()[0]]

    return arch, platforms[sys.platform]


def _get_lib_name(interface='libusb'):
    arch, _os = _get_arch_os()

    if _os == 'win':
        extension = 'dll'
    elif _os == 'linux':
        extension = 'so'
    else:
        raise OSError(
            'You OS is not supported.Exit.'
        )

    return 'liboptigatrust-{interface}-{os}-{arch}.{ext}'.format(interface=interface, os=_os, arch=arch, ext=extension)


def _load_lib(interface):
    libname = _get_lib_name(interface)

    old_path = os.getcwd()

    curr_path = os.path.normpath(os.path.abspath(os.path.join(os.path.dirname(__file__), "csrc", "lib")))
    lib_path = os.path.normpath(os.path.abspath(os.path.join(curr_path, libname)))

    os.chdir(curr_path)

    try:
        api = cdll.LoadLibrary(lib_path)
    except OSError:
        os.chdir(old_path)
        raise OSError('{}: Failed to find library {} in {}'.format(interface, libname, curr_path))
    api.exp_optiga_init.restype = c_int
    ret = api.exp_optiga_init()
    if ret != 0:
        os.chdir(old_path)
        raise OSError('{0}: Failed to connect'.format(interface))

    os.chdir(old_path)
    return api


def set_com_port_config(com_port):
    """
    A function to update globaly defined COM port which this module uses to connect, if uart is the target interface

    :param com_port: A string with 'COM39' like content
    """
    ini_path = os.path.normpath(os.path.abspath(os.path.join(os.path.dirname(__file__), "csrc", "lib", "optiga_comms.ini")))
    if not match(r"COM[0-9][0-9]", com_port) and not match(r"COM[0-9]", com_port):
        raise ValueError(
            'opts is specified, but value parameter is given: expected COMXX, your provided {0}. '
            'Use set_com_port(\'COM39\')'.format(com_port)
        )
    with open(ini_path, 'w', encoding='utf-8') as f:
        f.write(com_port)


def get_handler():
    global _optiga_cddl

    if _optiga_cddl is None:
        supported_interfaces = ('libusb', 'uart', 'i2c')
        initialised = False
        errors = list()
        """
        Here we try to probe which interface is actually in use, might be either libusb, i2c or uart
        We suppress stderr output of the libusb interface in case it's not connected to not confuse
        a user
        """
        for interface in supported_interfaces:
            try:
                _optiga_cddl = _load_lib(interface)
                print('Loaded: {0}'.format(_get_lib_name(interface)))
                initialised = True
            except OSError as error:
                errors.append(error)
                pass

        if not initialised:
            for err in errors:
                print(err)
            exit()

    return _optiga_cddl

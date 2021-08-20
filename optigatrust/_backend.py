#!/usr/bin/env python
"""This module defines backend operations and works as a gateway between the library and the actual hardware """

from ctypes import c_ubyte, c_ushort, c_int, POINTER, cdll
import os
import platform
import sys
from re import match

from serial.tools import list_ports


_OPTIGA_CDLL = None


__all__ = [
    'get_handler',
    '_set_com_port_config'
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


def _scan_com_ports():
    com_ports = list(list_ports.comports())
    for com_port in com_ports:
        # print("Found a com port: {0}: {1}".format(com_port.device, com_port.description))
        if com_port.description.startswith("USB Serial Device") or com_port.description.startswith("KitProg3"):
            _set_com_port_config(com_port.device)


def _load_lib(interface):
    if interface == 'uart':
        _scan_com_ports()

    libname = _get_lib_name(interface)

    old_path = os.getcwd()

    curr_path = os.path.normpath(os.path.abspath(os.path.join(os.path.dirname(__file__), "csrc", "lib")))
    lib_path = os.path.normpath(os.path.abspath(os.path.join(curr_path, libname)))

    os.chdir(curr_path)

    try:
        api = cdll.LoadLibrary(lib_path)
    except OSError as fail_to_load:
        os.chdir(old_path)
        raise OSError('{}: Failed to find library {} in {}'.format(interface, libname, curr_path)) from fail_to_load
    api.exp_optiga_init.restype = c_int
    ret = api.exp_optiga_init()
    if ret != 0:
        os.chdir(old_path)
        raise OSError('{0}: Failed to connect'.format(interface))

    os.chdir(old_path)
    return api


def _set_com_port_config(com_port):
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
    with open(ini_path, 'w', encoding='utf-8') as file:
        file.write(com_port)


def get_handler():
    # pylint: disable=global-statement
    # This is fair to use a global, as there should be only one instance of the communication stack initialized
    """
    A function which should return a communication instance of the connected hardware depending gon the interface

    """
    global _OPTIGA_CDLL

    if _OPTIGA_CDLL is None:
        supported_interfaces = ('libusb', 'uart', 'i2c')
        initialised = False
        errors = list()
        # Here we try to probe which interface is actually in use, might be either libusb, i2c or uart
        # We suppress stderr output of the libusb interface in case it's not connected to not confuse
        # a user
        for interface in supported_interfaces:
            try:
                _OPTIGA_CDLL = _load_lib(interface)
                print('Loaded: {0}'.format(_get_lib_name(interface)))
                initialised = True
                break
            except OSError as error:
                errors.append(error)

        if not initialised:
            for err in errors:
                print(err)
            sys.exit()

    return _OPTIGA_CDLL


def protected_update(api, manifest, fragments):
    # pylint: disable=global-statement
    # This is fair to use a global, as there should be only one instance of the communication stack initialized
    """
    A function which should return a communication instance of the connected hardware depending gon the interface

    :param api: api hardware handler

    :param manifest: a byte object containing a manifest data to be sent to the chip

    :param fragments: a list of individual bytes objects containing a payload to be sent to the chip
    """
    _manifest = (c_ubyte * len(manifest))(*manifest)

    api.exp_optiga_util_protected_update_start.argtypes = c_ubyte, POINTER(c_ubyte), c_ushort
    api.exp_optiga_util_protected_update_start.restype = c_int

    ret = api.exp_optiga_util_protected_update_start(c_ubyte(0x01), _manifest, len(_manifest))

    if ret != 0:
        print("Manifest [{0}]: ".format(len(_manifest)).join('{:02x} '.format(x) for x in list(_manifest)))
        print(len(_manifest))
        raise IOError('Function can\'t be executed. Error {0}'.format(hex(ret)))

    for count, fragment in enumerate(fragments[:-1]):
        _fragment = (c_ubyte * len(fragment))(*fragment)

        api.exp_optiga_util_protected_update_continue.argtypes = POINTER(c_ubyte), c_ushort
        api.exp_optiga_util_protected_update_continue.restype = c_int

        ret = api.exp_optiga_util_protected_update_continue(_fragment, len(_fragment))

        if ret != 0:
            print("Fragment {0} [{1}]: ".
                  format(count, len(_fragment)).
                  join('{:02x} '.format(x) for x in list(_fragment)))
            raise IOError('Function can\'t be executed. Error {0}'.format(hex(ret)))

    final_fragment = (c_ubyte * len(fragments[-1]))(*fragments[-1])

    api.exp_optiga_util_protected_update_final.argtypes = POINTER(c_ubyte), c_ushort
    api.exp_optiga_util_protected_update_final.restype = c_int

    ret = api.exp_optiga_util_protected_update_final(final_fragment, len(final_fragment))

    if ret != 0:
        print("Final Fragment [{0}]: ".
              format(len(final_fragment)).
              join('{:02x} '.format(x) for x in list(final_fragment)))
        raise IOError('Function can\'t be executed. Error {0}'.format(hex(ret)))

    return ret

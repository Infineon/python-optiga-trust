#!/usr/bin/env python
"""This module defines backend operations and works as a gateway between the library and the actual hardware """

from ctypes import c_ubyte, c_ushort, c_int, POINTER, cdll, memmove, byref
import os
import platform
import sys
from re import match

from serial.tools import list_ports

from optigatrust.enums import x, m1, m3, m2id2, charge


_OPTIGA_CDLL = None


__all__ = [
    'get_handler',
    'lookup_optiga',
    'read_data',
    'read_meta',
    'write_data',
    'write_meta',
    'protected_update',
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
        print(fail_to_load)
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
    if not match(r"COM[0-9][0-9]", com_port) and not match(r"COM[0-9]", com_port) and not match(r"/dev/ttyACM[0-9]*", com_port):
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


def lookup_optiga(api):
    """
    A function which should return a valid chip descriptor and its name

    :param api: api hardware handler
    """
    api.exp_optiga_util_read_data.argtypes = c_ushort, c_ushort, POINTER(c_ubyte), POINTER(c_ushort)
    api.exp_optiga_util_read_data.restype = c_int
    api.exp_optiga_util_read_metadata.argtypes = c_ushort, POINTER(c_ubyte), POINTER(c_ushort)
    api.exp_optiga_util_read_metadata.restype = c_int

    c_d = (c_ubyte * 1700)()
    c_dlen = c_ushort(1700)

    ret = api.exp_optiga_util_read_data(c_ushort(0xE0C2), 0, c_d, byref(c_dlen))

    if ret == 0 and not all(_d == 0 for _d in list(bytes(c_d))):
        data = (c_ubyte * c_dlen.value)()
        memmove(data, c_d, c_dlen.value)
        _bytes = bytearray(data)
    else:
        _bytes = bytearray(0)

    _fw_build = int.from_bytes(_bytes[25:27], byteorder='big')

    # Trust M1 or Charge
    if _fw_build in {0x501, 0x624, 0x751, 0x802, 0x809}:
        ret = api.exp_optiga_util_read_metadata(c_ushort(0xe0fc), data, byref(c_dlen))
        if ret != 0:
            # it means that we work with OPTIGA Trust Charge
            return charge, 'OPTIGA™ Trust Charge V1 (SLS32AIA020U2/3)'

        return m1, 'OPTIGA™ Trust M V1 (SLS32AIA010MH/S)'
    # Trust M2 ID2 or M3
    if _fw_build in {0x2440}:
        ret = api.exp_optiga_util_read_metadata(c_ushort(0xe0f1), data, byref(c_dlen))
        if ret != 0:
            # it means that we work with OPTIGA Trust M2 ID2
            return m2id2, 'OPTIGA™ Trust M2 ID2 (SLS32AIA010I2/3)'

        return m3, 'OPTIGA™ Trust M V3 (SLS32AIA010ML/K)'

    if _fw_build in {0x510, 0x715, 0x1048, 0x1112, 0x1118}:
        return x, 'OPTIGA™ Trust X (SLS32AIA020X2/4)'

    return None, ''


def read_data(api, object_id, offset):
    """
    A function which uses the correct api call to extract data from the chip

    :param api: api hardware handler

    :param object_id: an integer value from which object id to read

    :param offset: an integer value which defines data offset

    :raises
        - IOError - in case data read is not possible an IOError exception is generated
    """
    api.exp_optiga_util_read_data.argtypes = c_ushort, c_ushort, POINTER(c_ubyte), POINTER(c_ushort)
    api.exp_optiga_util_read_data.restype = c_int

    ctypes_data = (c_ubyte * 1700)()
    c_dlen = c_ushort(1700)

    ret = api.exp_optiga_util_read_data(c_ushort(object_id), offset, ctypes_data, byref(c_dlen))

    if ret == 0:
        result_data = (c_ubyte * c_dlen.value)()
        memmove(result_data, ctypes_data, c_dlen.value)
        data = bytearray(result_data)
    else:
        raise IOError('Function can\'t be executed. Error {0}'.format(hex(ret)))

    return data


def read_meta(api, object_id):
    """
    A function which uses the correct api call to extract metadata from the chip

    :param api: api hardware handler

    :param object_id: an integer value from which object id to read

    :raises
        - IOError - in case data read is not possible an IOError exception is generated
    """

    api.exp_optiga_util_read_metadata.argtypes = c_ushort, POINTER(c_ubyte), POINTER(c_ushort)
    api.exp_optiga_util_read_metadata.restype = c_int

    c_meta = (c_ubyte * 100)()
    c_mlen = c_ushort(100)

    ret = api.exp_optiga_util_read_metadata(c_ushort(object_id), c_meta, byref(c_mlen))

    if ret == 0:
        result_meta = (c_ubyte * c_mlen.value)()
        memmove(result_meta, c_meta, c_mlen.value)
        meta = bytearray(result_meta)
    else:
        raise IOError('Function can\'t be executed. Error {0}'.format(hex(ret)))

    return meta


def write_data(api, object_id, offset, data):
    """
    A function which uses the correct api call to write data to the chip

    :param api: api hardware handler

    :param object_id: an integer value from which object id to read

    :param offset: an integer value which defines data offset

    :param data: a bytes object with data to be send

    :raises
        - IOError - in case data read is not possible an IOError exception is generated
    """
    api.exp_optiga_util_write_data.argtypes = c_ushort, c_ubyte, c_ushort, POINTER(c_ubyte), c_ushort
    api.exp_optiga_util_write_data.restype = c_int

    ctypes_data = (c_ubyte * len(data))(*data)

    ret = api.exp_optiga_util_write_data(c_ushort(object_id), 0x40, offset, ctypes_data, len(ctypes_data))

    if ret != 0:
        raise IOError('Function can\'t be executed. Error {0}'.format(hex(ret)))


def write_meta(api, object_id, meta):
    """
    A function which uses the correct api call to write metadata to the chip

    :param api: api hardware handler

    :param object_id: an integer value from which object id to read

    :param meta: a bytes object with metadata to be send

    :raises
        - IOError - in case data read is not possible an IOError exception is generated
    """
    ctypes_meta = (c_ubyte * len(meta))(*meta)

    api.exp_optiga_util_write_metadata.argtypes = c_ushort, POINTER(c_ubyte), c_ubyte
    api.exp_optiga_util_write_metadata.restype = c_int

    ret = api.exp_optiga_util_write_metadata(c_ushort(object_id), ctypes_meta, len(ctypes_meta))

    if ret != 0:
        raise IOError('Function can\'t be executed. Error {0}'.format(hex(ret)))

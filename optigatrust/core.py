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
from collections import namedtuple
import struct

from optigatrust.const import x, m1, m3, m2id2, charge

__all__ = [
    'Settings',
    'Descriptor',
    'Object',
    'ValueMap',
    'init',
    'random',
    'get_info',
    'lifecycle_states',
    'key_usages',
    'key_usages_swaped',
    'meta_tags',
    'meta_tags_swaped',
    'algorithms',
    'algorithms_swaped',
    'access_conditions_ids',
    'access_conditions_ids_swaped',
    'data_object_types',
    'data_object_types_swaped',
    'parse_raw_meta',
    'prepare_raw_meta',
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
    arch, os = _get_arch_os()

    if os == 'win':
        extension = 'dll'
    if os == 'linux':
        extension = 'so'

    return 'liboptigatrust-{interface}-{os}-{arch}.{ext}'.format(interface=interface, os=os, arch=arch, ext=extension)


def _load_lib(interface):
    libname = _get_lib_name(interface)

    old_path = os.getcwd()

    curr_path = os.path.abspath(os.path.dirname(__file__) + "/csrc/lib/")

    os.chdir(curr_path)
    if os.path.exists(os.path.join(curr_path, libname)):
        api = cdll.LoadLibrary(os.path.join(curr_path, libname))
    else:
        api = None
        os.chdir(old_path)
        raise OSError('Unable to find library in {}. Look for {}'.format(curr_path, libname))
    api.exp_optiga_init.restype = c_int
    ret = api.exp_optiga_init()
    if ret != 0:
        os.chdir(old_path)
        raise OSError('Failed to initialise the chip. Exit.')

    os.chdir(old_path)
    return api


UID = namedtuple("UID", "cim_id platform_id model_id rommask_id chip_type batch_num x_coord y_coord fw_id fw_build")
_optiga_descriptor = None


class Settings:
    def __init__(self):
        self._current_limit = int.from_bytes(Object(0xe0c4).read(), "big")
        self._sleep_activation_delay = int.from_bytes(Object(0xe0c3).read(), "big")
        _uid = Object(0xe0c2).read(force=True)
        self._uid = UID(int.from_bytes(_uid[0:1], byteorder='big'),
                        int.from_bytes(_uid[1:2], byteorder='big'),
                        int.from_bytes(_uid[2:3], byteorder='big'),
                        int.from_bytes(_uid[3:5], byteorder='big'),
                        int.from_bytes(_uid[5:11], byteorder='big'),
                        int.from_bytes(_uid[11:17], byteorder='big'),
                        int.from_bytes(_uid[17:19], byteorder='big'),
                        int.from_bytes(_uid[19:21], byteorder='big'),
                        int.from_bytes(_uid[21:25], byteorder='big'),
                        int.from_bytes(_uid[25:27], byteorder='big'))
        self._security_status = int.from_bytes(Object(0xe0c1).read(), "big")
        self._global_lifecycle_state = lifecycle_states[int.from_bytes(Object(0xe0c0).read(), 'big')]
        self._security_event_counter = int.from_bytes(Object(0xe0c5).read(), "big")

    @property
    def current_limit(self):
        return self._current_limit

    @current_limit.setter
    def current_limit(self, val: int):
        Object(0xe0c4).write(bytes([val]))

    @property
    def sleep_activation_delay(self):
        return self._sleep_activation_delay

    @sleep_activation_delay.setter
    def sleep_activation_delay(self, val: int):
        Object(0xe0c3).write(bytes([val]))

    @property
    def uid(self):
        return self._uid

    @property
    def global_lifecycle_state(self):
        return self._global_lifecycle_state

    @global_lifecycle_state.setter
    def global_lifecycle_state(self, val: str):
        if val not in lifecycle_states.values():
            raise ValueError(
                'Wrong lifecycle state. Expected {0}, your provided {1}'.format(lifecycle_states, val)
            )
        for code, state in lifecycle_states.items():
            if state == val:
                Object(0xe0c0).write(bytes(state))

    @property
    def security_status(self):
        return self._security_status

    @property
    def security_event_counter(self):
        self._security_event_counter = int.from_bytes(Object(0xe0c5).read(), "big")
        return self._security_event_counter


class Descriptor:
    def __init__(self, api, name, object_id, key_id, session_id, rng, key_usage, curves):
        self.api = api
        self.name = name
        self.object_id = object_id
        self.object_id_values = set(item.value for item in self.object_id)
        self.key_usage = key_usage
        self.key_usage_values = set(item.value for item in self.key_usage)
        self.key_id = key_id
        self.key_id_values = set(item.value for item in self.key_id)
        self.session_id = session_id
        self.session_id_values = set(item.value for item in self.session_id)
        self.rng = rng
        self.rng_values = set(item.value for item in self.rng)
        self.curves = curves
        self.curves_values = set(item.value for item in self.curves)
        self.enabled = True
        self._settings = None

    @property
    def settings(self):
        return self._settings

    @settings.setter
    def settings(self, data: Settings):
        self._settings = data


def init():
    """
    This function either initialises non-initialised communication channel between the chip and the application, or
    returns an existing communication
    ONLY ONE Optiga Instance is supported

    :param None:

    :raises:
        OSError: If some problems occured during the initialisation of the library or the chip

    :returns:
        a CDLL Instance
    """
    global _optiga_descriptor

    if _optiga_descriptor is None:
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

        consts, name = _lookup_optiga(api)
        _optiga_descriptor = Descriptor(
            api=api,
            name=name,
            object_id=consts.ObjectId,
            key_id=consts.KeyId,
            session_id=consts.SessionId,
            key_usage=consts.KeyUsage,
            rng=consts.Rng,
            curves=consts.Curves
        )
        _optiga_descriptor.settings = Settings()
        get_info()

    return _optiga_descriptor


def get_info():
    optiga = init()
    settings = optiga.settings
    print("================== OPTIGA Trust Chip Info ==================")
    print('{0:<30}{1:^10}:{2}'.format("Firmware Identifier", "[dwFirmwareIdentifier]", hex(settings.uid.fw_id)))
    print('{0:<30}{1:^10}:{2}'.format("Build Number", "[rgbESWBuild]", hex(settings.uid.fw_build)))
    print('{0:<30}{1:^10}:{2}'.format("Current Limitation", "[OID: 0xE0C4]", hex(settings.current_limit)))
    print('{0:<30}{1:^10}:{2}'.format("Sleep Activation Delay", "[OID: 0xE0C3]", hex(settings.sleep_activation_delay)))
    print('{0:<30}{1:^10}:{2}'.format("Global Lifecycle State", "[OID: 0xE0C0]", settings.global_lifecycle_state))
    print('{0:<30}{1:^10}:{2}'.format("Security Status", "[OID: 0xE0C1]", hex(settings.security_status)))
    print('{0:<30}{1:^10}:{2}'.format("Security Event Counter", "[OID: 0xE0C5]", hex(settings.security_event_counter)))
    print("============================================================")


def _lookup_optiga(api):
    api.exp_optiga_util_read_data.argtypes = c_ushort, c_ushort, POINTER(c_ubyte), POINTER(c_ushort)
    api.exp_optiga_util_read_data.restype = c_int

    d = (c_ubyte * 1700)()
    c_dlen = c_ushort(1700)

    ret = api.exp_optiga_util_read_data(c_ushort(0xE0C2), 0, d, byref(c_dlen))

    if ret == 0 and not all(_d == 0 for _d in list(bytes(d))):
        data = (c_ubyte * c_dlen.value)()
        memmove(data, d, c_dlen.value)
        _bytes = bytearray(data)
    else:
        _bytes = bytearray(0)

    _fw_build = int.from_bytes(_bytes[25:27], byteorder='big')

    if _fw_build in {0x809}:
        return m1, "OPTIGA™ Trust M V1 (SLS32AIA010MH/S)"
    if _fw_build in {0x2440}:
        return m3, "OPTIGA™ Trust M V3 (SLS32AIA010ML/K)"
    else:
        return x, "OPTIGA™ Trust X (SLS32AIA020X2/4)"


def random(n, trng=True):
    """
    This function generates a random number

    :param n:
        how much randomness to generate. Valid values are from 8 to 256

    :param trng:
        If True the a True Random Generator will be used, otherwise Deterministic Random Number Generator

    :raises:
        - TypeError - when any of the parameters are of the wrong type
        - OSError - when an error is returned by the chip initialisation library

    :returns:
        Bytes object with randomness
    """
    optiga = init()
    api = optiga.api

    api.exp_optiga_crypt_random.argtypes = c_byte, POINTER(c_ubyte), c_ushort
    api.exp_optiga_crypt_random.restype = c_int
    p = (c_ubyte * n)()

    if trng is True:
        ret = api.exp_optiga_crypt_random(optiga.rng.TRNG.value, p, len(p))
    else:
        ret = api.exp_optiga_crypt_random(optiga.rng.DRNG.value, p, len(p))

    if ret == 0:
        return bytes(p)
    else:
        return bytes(0)


lifecycle_states = {
    1: 'creation',
    3: 'initalisation',
    7: 'operational',
    15: 'termination'
}

key_usages = {
    'authentication': b'\x01',
    'encryption': b'\x02',
    'sign': b'\x10',
    'key_agreement': b'\x20',
}

key_usages_swaped = {y: x for x, y in key_usages.items()}

meta_tags = {
    'execute': b'\xd3',
    'change': b'\xd0',
    'read': b'\xd1',
    'metadata': b'\x20',
    'lcso': b'\xc0',
    'version': b'\xc1',
    'max_size': b'\xc4',
    'used_size': b'\xc5',
    'algorithm': b'\xe0',
    'key_usage': b'\xe1',
    'type': b'\xe8',
    'reset_type': b'\xf0',
}

meta_tags_swaped = {y: x for x, y in meta_tags.items()}

algorithms = {
    'nistp256r1': b'\x03',
    'nistp384r1': b'\x04',
    'nistp512r1': b'\x05',
    'brainpool256r1': b'\x13',
    'brainpool384r1': b'\x15',
    'brainpool521r1': b'\x16',
    'rsa1024': b'\x41',
    'rsa2048': b'\x42',
    'aes128': b'\x81',
    'aes192': b'\x82',
    'aes256': b'\x83',
    'sha256': b'\xe2'
}

algorithms_swaped = {y: x for x, y in algorithms.items()}

access_conditions_ids = {
    'always': b'\x00',
    # 2 bytes, e.g. Enable access if boot phase flag in Security Status application is set → 0x10, 0x20
    # Note: SetDataObject with Param = erase&write clears all bits and with Param = write clears all corresponding
    # bits not set to 1 in data to be written
    'sec_sta_g': b'\x10',
    # 3 bytes, for instance data object read is allowed only under shielded connection using a pre shared secret
    # 1) Read, Conf, Binding Secret (e.g. 0xD1, 0x03, 0x20, 0xE1, 0x40) In case of reading a data object (e.g. using
    # GetDataObject), the shielded connection must be established already using the specified Binding secret (e.g.
    # 0xE140) and the response is requested with protection (encrypted).
    # 2) Change, Conf, Binding Secret (e.g. 0xD0,
    # 0x03, 0x20, 0xE1, 0x40) In case of writing a data object (e.g. using SetDataObject), the shielded connection
    # must be established already using the specified pre-shared secret (0xE140) and the command is sent with
    # protection (encrypted).
    # 3) Execute, Conf, Binding Secret (e.g. 0xD3, 0x03, 0x20, 0xE1, 0x40) In case of using a
    # data object with an internal operation (e.g. using DeriveKey from a pre-shared secret), the shielded connection
    # must be established already using the specified binding secret (0xE140) and the command is sent protection (
    # encrypted).
    # 4) Change, Conf, Protected Update Secret → (e.g. 0xD0, 0x03, 0x20, 0xF1, 0xD0) In case of writing a
    # data object (using SetObjectProtected), the manifest must specify the same Protected Update Secret (e.g. 0xF1,
    # 0xD0) which is specified in the object metadata. This enforces to use the defined Protected Update Secret to
    # decrypt the object data in fragments.
    # Notes: Conf (Protected Update Secret) must be used in association(
    # Operator AND) with Integrity (Trust Anchor), to enforce the right Protected Update Secret to be used to decrypt
    # the object data as part of SetObjectProtected. If Conf (Protected Update Secret) not specified in the metadata
    # access conditions, SetObjectProtected uses Protected Update Secret specified in the manifest, to decrypt the
    # object data as part of fragments. The usage of this identifier is to enforce the right secret used (Integrity
    # Trust Anchor, Operator AND, Confidentiality Protected Update Secret OID). The Protected Update Secret must not
    # same as the target data object to be updated.
    'conf': b'\x20',
    # 3 byte; Value, Key Reference
    # (e.g. Int first Session Key → 0x21, 0xF1, 0xF0)
    # 1) Read, Int, Binding Secret (e.g. 0xD1, 0x03, 0x21, 0xE1, 0x40)
    # In case of reading a data object (e.g. using GetDataObject), the shielded connection must be established already
    # using the specified pre-shared secret (0xE140) and the response is requested with protection (MAC).
    # 2) Change, Int, Binding Secret (e.g. 0xD0, 0x03, 0x21, 0xE1, 0x40)
    # In case of writing a data object (e.g. using SetDataObject), the shielded connection must be established already
    # using the specified pre-shared secret (0xE140) and the command is sent with protection (MAC).
    # 3) Execute, Int, Binding Secret (e.g. 0xD3, 0x03, 0x21, 0xE1, 0x40)
    # In case of using a data object with an internal operation (e.g. using DeriveKey from a pre-shared secret), the
    # shielded connection must be established already using the specified pre-shared secret (0xE140) and the command
    # is sent with protection (MAC).
    # 4) Change, Int, Trust Anchor (e.g. 0xD0, 0x03, 0x21, 0xE0, 0xEF)
    # In case of writing a data object (e.g. using SetObjectProtected), the signature associated with the meta data
    # in the manifest must be verified with the addressed trust anchor (e.g. 0xE0EF) in the access conditions. In case
    # of SetObjectProtected command, the change access conditions of target OID must have Integrity access condition
    # identifier with the respective Trust Anchor.
    'int': b'\x21',
    # 3 byte; Value, Reference (Authorization Reference OID)
    # (e.g. Auto → 0x23, 0xF1, 0xD0)
    'auto': b'\x23',
    # 3 byte; Value, Counter Reference
    # (e.g. Linked Counter 1 → 0x40, 0xE1, 0x20)
    # For example, The arbitrary data object holds a pre-shared secret and this secret is allowed to be used for
    # key derivation
    # (DeriveKey) operations to a limited number of times. To enable this, choose a counter object
    # (updated with maximum allowed limit) and assign the counter data object in the EXE access condition of arbitrary
    # data object as shown below.
    # (e.g. EXE, Luc, Counter Object → 0xD3, 0x03, 0x40, 0xE1, 0x20)
    # The counter data objects gets updated (counter value gets incremented by 1 up to maximum limit)
    # automatically when the DeriveKey command is performed.
    'luc': b'\x40',
    # 3 byte; Value, Qualifier, Reference
    # (e.g. LcsG < op → 0x70, 0xFC, 0x07)
    'lcsg': b'\x70',
    # 2 byte; Value
    # (e.g. Enable access if boot phase flag in Security Status application is set → 0x90, 0x20)
    # Note: SetDataObject with Param = erase&write clears all bits and with Param = write clears all corresponding
    # bits not set to 1 in data to be written
    'sec_sta_a': b'\x90',
    # 3 byte; Value, Qualifier, Reference
    # (e.g. LcsA > in → 0xE0, 0xFB, 0x03)
    'lcsa': b'\xe0',
    # 3 byte; Value, Qualifier, Reference
    # (e.g. LcsO < op → 0xE1, 0xFC, 0x07)
    'lcso': b'\xe1',
    '==': b'\xfa',
    '>': b'\xfb',
    '<': b'\xfc',
    '&&': b'\xfd',
    '||': b'\xfe',
    'never': b'\xff'
}

access_conditions_ids_swaped = {y: x for x, y in access_conditions_ids.items()}

data_object_types = {
    # SRM: BSTR. The Byte String data object type is represented by a sequence of bytes, which could be addressed by
    # offset and length.
    'byte_string': b'\x00',
    # SRM: UPCTR. The Up-counter data type implements a counter with a current value which could be increased only
    # and a threshold terminating the counter.
    'up_counter': b'\x01',
    # SRM: TA. The Trust Anchor data type contains a single X.509 certificate which could be used in various commands
    # requiring a root of trust.
    'trust_anchor': b'\x11',
    # SRM: DEVCERT. The Device Identity data type contains a single X.509 certificate or a chain of certificates
    # (TLS, USB-Type C, ...) which was issued to vouch for the cryptographic identity of the end-device.
    'device_cert': b'\x12',
    # SRM: PRESSEC. The Pre-shared Secret contains a binary data string which makes up a pre-shared secret for various
    # purposes (FW-decryption, ...).
    'pre_sh_secret': b'\x21',
    # SRM: PTFBIND. The Platform Binding contains a binary data string which makes up a pre-shared secret for platform
    # binding (e.g. used for OPTIGA™ Shielded Connection).
    'platform_binding': b'\x22',
    # SRM: UPDATESEC. The Protected Update Secret contains a binary data string which makes up a pre-shared secret for
    # confidentiality protected update of data or key objects. The maximum length is limited to 64 bytes, even if the
    # hosting data object has a higher maximum length.
    'update_secret': b'\x23',
    # SRM: AUTOREF. The Authorization Reference contains a binary data string which makes up a reference value for
    # verifying an external entity (admin, user, etc.) authorization.
    'authorization_ref': b'\x31'
}

data_object_types_swaped = {y: x for x, y in data_object_types.items()}


def parse_raw_meta(meta: bytes):
    """
    This function should process the given metadata and return it in a human readable form.

    :param meta:
        metadata represented in bytes

    :raises:
        - ValueError - when any of the parameters contain an invalid value
        - TypeError - when any of the parameters are of the wrong type
        - OSError - when an error is returned by the chip initialisation library

    :returns:
        A dictionary of the following format::

            {
                'read': 'always'
                'execute': ['lcso', '<', 'operational']
            }

    """
    global access_conditions_ids_swaped
    global meta_tags_swaped
    if not isinstance(meta, bytes) and not isinstance(meta, bytearray):
        raise TypeError(
            'Metadata (meta) should be in bytes form, you provided {0}'.format(type(meta))
        )
    meta_unpacked = list(struct.unpack(str(len(meta)) + 'c', meta))
    meta_itr = iter(meta_unpacked)
    # First byte is always \x20
    # For instance
    # [ b'\x20',
    #   b'\x17',
    #   b'\xc0', b'\x01', b'\x01',
    #   b'\xc4', b'\x02', b'\x06', b'\xc0',
    #   b'\xc5', b'\x02', b'\x01', b'\xe5',
    #   b'\xd0', b'\x01', b'\xff',
    #   b'\xd1', b'\x01', b'\x00',
    #   b'\xd3', b'\x01', b'\x00',
    #   b'\xe8', b'\x01', b'\x12' ]
    # We skip the very first tag, then record the length o the meta data, then go tag by tag (line by line here).
    # Some tags, like lcso or algorithm have a different value which should be interepeted differently
    next(meta_itr)
    meta_size = int.from_bytes(next(meta_itr), "big")
    if meta_size == 0:
        return None
    if meta_size < 0:
        raise ValueError(
            'Metadata size can\'t be less than zero. Ou have {0}'.format(meta_size)
        )
    # 64 for is the maximum
    if meta_size > 62:
        raise ValueError(
            'Metadata Size can\'t be more than 64 bytes. You have {0}'.format(meta_size)
        )
    meta_parsed = dict()
    try:
        while True:
            tag = meta_tags_swaped[next(meta_itr)]
            tag_size = int.from_bytes(next(meta_itr), 'big')
            if tag_size == 0:
                return None
            if tag_size < 0:
                raise ValueError(
                    'Metadata size can\'t be less than zero. Ou have {0}'.format(meta_size)
                )
            if tag == 'used_size' or tag == 'max_size':
                if tag_size == 2:
                    meta_parsed[tag] = (int.from_bytes(next(meta_itr), 'big') << 8) + \
                                          int.from_bytes(next(meta_itr), 'big')
                elif tag_size == 1:
                    meta_parsed[tag] = int.from_bytes(next(meta_itr), 'big')
                else:
                    raise ValueError(
                        'Tag Size for Max or Used Sizes should be either 2 or 1, you have {0}'.format(tag_size)
                    )
                continue
            if tag == 'type':
                meta_parsed[tag] = data_object_types_swaped[next(meta_itr)]
                continue
            if tag == 'algorithm':
                meta_parsed[tag] = algorithms_swaped[next(meta_itr)]
                continue
            if tag == 'key_usage':
                key_usage_bytes = int.from_bytes(next(meta_itr), 'big')
                tag_data = list()
                if key_usage_bytes & int.from_bytes(key_usages['authentication'], 'big'):
                    tag_data.append('authentication')
                if key_usage_bytes & int.from_bytes(key_usages['encryption'], 'big'):
                    tag_data.append('encryption')
                if key_usage_bytes & int.from_bytes(key_usages['sign'], 'big'):
                    tag_data.append('sign')
                if key_usage_bytes & int.from_bytes(key_usages['key_agreement'], 'big'):
                    tag_data.append('key_agreement')
                meta_parsed[tag] = tag_data
                continue
            tag_data = list()
            i = 0
            while i < tag_size:
                _id = next(meta_itr)
                i += 1
                if _id in access_conditions_ids_swaped:
                    # Conf, Int, auto and luc have as the last two bytes a reference to the oid used for the expression
                    # it is just another OID from the system
                    if _id == access_conditions_ids['conf'] \
                            or _id == access_conditions_ids['int'] \
                            or _id == access_conditions_ids['auto'] \
                            or _id == access_conditions_ids['luc']:
                        tag_data.append(access_conditions_ids_swaped[_id])
                        tag_data.append(next(meta_itr).hex())
                        tag_data.append(next(meta_itr).hex())
                        i += 2
                    else:
                        tag_data.append(access_conditions_ids_swaped[_id])
                # if we didn't meet the number, it should be in the lifecycle states
                elif int.from_bytes(_id, "big") in lifecycle_states:
                    tag_data.append(lifecycle_states[int.from_bytes(_id, "big")])
                else:
                    tag_data.append(_id.hex())
            if tag_size == 1:
                tag_data = ''.join(tag_data)
            meta_parsed[tag] = tag_data
    except StopIteration:
        return meta_parsed


def prepare_raw_meta(new_meta: dict):
    """
    This function takes as an imput json-like formatted dictionary and translates it to the data to write into the chip

    :param new_meta:
        A dictionary (json like formatted) with new metadata; e.g.::

            {
                "lcso": "creation",
                "change": [
                    "lcso",
                    "<",
                    "operational"
                ],
                "execute": "always",
                "algorithm": "nistp384r1",
                "key_usage": "21"
            }

    :raises:
        - ValueError - when any of the parameters contain an invalid value
        - TypeError - when any of the parameters are of the wrong type
        - OSError - when an error is returned by the chip initialisation library
    :returns:
        a bytearray with resulting metadata to write into the chip
    """
    meta = list()
    # 0x20 should go first
    meta.append(32)
    # then you have length
    meta.append(0)
    for key, value in new_meta.items():
        if key not in meta_tags:
            raise ValueError(
                'Wrong value. Accepted values: {0}, you provided {1}'.format(meta_tags.keys(), key)
            )
        meta.append(int.from_bytes(meta_tags[key], 'big'))
        # Update the size
        meta[1] += 1
        if key == 'used_size' or key == 'max_size':
            raise ValueError(
                'The used size tag and max size tag can#t be set by user'
            )
        if key == 'type':
            if value not in data_object_types:
                raise ValueError(
                    'Value for Type meta tag isn\'t found. '
                    'Accepted values {0}, you provided {1}'.format(data_object_types.keys(), key)
                )
            meta.append(int.from_bytes(data_object_types[value], 'big'))
            # Update the size
            meta[1] += 1
            continue
        if key == 'algorithm':
            if value not in algorithms:
                raise ValueError(
                    'Value for Algorithm meta tag isn\'t found. '
                    'Accepted values {0}, you provided {1}'.format(algorithms.keys(), key)
                )
            meta.append(int.from_bytes(algorithms[value], 'big'))
            # Update the size
            meta[1] += 1
            continue
        if key == 'key_usage':
            # the value should be of type list()
            if not isinstance(value, list):
                raise TypeError(
                    'key usage tag should be provided in the form of a lost for instance [\'x\', \'y\', \'z\']'
                )
            for i in value:
                if i not in key_usages:
                    raise ValueError(
                        'key usage isn\'t supported. Supported values {0}, you provided {1}'.format(key_usages, i)
                    )
                meta.append(int(i))
                # Update the size
                meta[1] += 1
            continue
        if isinstance(value, list):
            meta.append(len(value))
            meta[1] += 1
            for element in value:
                if element not in access_conditions_ids:
                    raise ValueError(
                        'Value for Access Condition isn\'t found. '
                        'Accepted values {0}, you provided {1}'.format(access_conditions_ids.keys(), element)
                    )
                meta.append(int.from_bytes(access_conditions_ids[element], 'big'))
                meta[1] += 1
        else:
            meta.append(1)
            meta[1] += 1
            meta.append(int.from_bytes(access_conditions_ids[value], 'big'))
            meta[1] += 1
    return bytearray(meta)


class Object:
    """
    A class used to represent an Object on the OPTIGA Trust Chip

    :ivar id: the id of the object; e.g. 0xe0e0
    :vartype id: int

    :ivar optiga: the instance of the OPTIGA handler used internally by the Object class
    :vartype optiga: core.Descriptor

    :ivar updated: This boolean variable notifies whether metadata or data has been updated and this can bu used to
    notify other modules to reread data if needed
    :vartype updated: bool
    """

    def __init__(self, _id):
        """
        This class

        :param _id:
            an Object ID which you would like to initialise; e.g. 0xe0e0

        return:
            self
        """
        self.id = _id
        self.optiga = init()
        # A flag to understand whether the object was recently updated
        self.updated = False

    @property
    def meta(self):
        """ A dictionary of the metadata present right now on the chip for the given object. It is writable,
        so user can update the metadata assigning the value to it
        """
        _array_meta = self.read_raw_meta()
        return parse_raw_meta(_array_meta)

    @meta.setter
    def meta(self, new_meta: dict):
        meta = prepare_raw_meta(new_meta)
        self.write_raw_meta(meta)

    def read(self, offset=0, force=False):
        """
        This function helps to read the data stored on the chip

        :param offset:
            An optional parameter defining whether you want to read the data with offset

        :param force:
            This is a parameter which can be used to try to read the data even if id can't be somehow finden

        :raises:
            - ValueError - when any of the parameters contain an invalid value
            - TypeError - when any of the parameters are of the wrong type
            - OSError - when an error is returned by the chip initialisation library

        :return:
            bytearray with the data
        """
        api = self.optiga.api

        if offset > 1700:
            raise ValueError("offset should be less than the limit of 1700 bytes")

        if force is False:
            if self.id not in self.optiga.object_id_values:
                raise TypeError(
                    "object_id not found. \n\r Supported = {0},\n\r  "
                    "Provided = {1}".format(list(hex(self.optiga.object_id)), self.id))

        api.exp_optiga_util_read_data.argtypes = c_ushort, c_ushort, POINTER(c_ubyte), POINTER(c_ushort)
        api.exp_optiga_util_read_data.restype = c_int

        d = (c_ubyte * 1700)()
        c_dlen = c_ushort(1700)

        ret = api.exp_optiga_util_read_data(c_ushort(self.id), offset, d, byref(c_dlen))

        if ret == 0:
            data = (c_ubyte * c_dlen.value)()
            memmove(data, d, c_dlen.value)
            _bytes = bytearray(data)
        else:
            raise IOError('Function can\'t be executed. Error {0}'.format(hex(ret)))

        return _bytes

    def write(self, data, offset=0):
        """
        This function helps to write the data onto the chip

        :param data:
            Data to write, should be either bytes of bytearray

        :param offset:
            An optional parameter defining whether you want to read the data with offset

        :raises
            - ValueError - when any of the parameters contain an invalid value
            - TypeError - when any of the parameters are of the wrong type
            - OSError - when an error is returned by the chip initialisation library
        """
        api = self.optiga.api

        if not isinstance(data, bytes) and not isinstance(data, bytearray):
            raise TypeError("data should be bytes type")

        if self.id not in self.optiga.object_id_values:
            raise TypeError(
                "object_id not found. \n\r Supported = {0},\n\r  "
                "Provided = {1}".format(list(hex(self.optiga.object_id)), self.id))

        if len(data) > 1700:
            raise ValueError("length of data exceeds the limit of 1700")

        if offset > 1700:
            raise ValueError("offset should be less than the limit of 1700 bytes")

        api.exp_optiga_util_write_data.argtypes = c_ushort, c_ubyte, c_ushort, POINTER(c_ubyte), c_ushort
        api.exp_optiga_util_write_data.restype = c_int

        _data = (c_ubyte * len(data))(*data)

        ret = api.exp_optiga_util_write_data(c_ushort(self.id), 0x40, offset, _data, len(data))

        if ret != 0:
            raise IOError('Function can\'t be executed. Error {0}'.format(hex(ret)))

        self.updated = True

    def read_raw_meta(self) -> bytearray:
        """
        This function helps to read the metadata associated with the data object stored on the chip

        :raises:
            - ValueError - when any of the parameters contain an invalid value
            - TypeError - when any of the parameters are of the wrong type
            - OSError - when an error is returned by the chip initialisation library

        :returns:
            bytearray with the data
        """
        api = self.optiga.api

        if (self.id not in self.optiga.object_id_values) and (self.id not in self.optiga.key_id_values):
            raise TypeError(
                "data_id not found. \n\r Supported = {0} and {1},\n\r  Provided = {2}".format(
                    list(hex(self.optiga.object_id)),
                    list(hex(self.optiga.key_id)),
                    self.id)
            )

        api.exp_optiga_util_read_metadata.argtypes = c_ushort, POINTER(c_ubyte), POINTER(c_ushort)
        api.exp_optiga_util_read_metadata.restype = c_int

        d = (c_ubyte * 100)()
        c_dlen = c_ushort(100)

        ret = api.exp_optiga_util_read_metadata(c_ushort(self.id), d, byref(c_dlen))

        if ret == 0:
            data = (c_ubyte * c_dlen.value)()
            memmove(data, d, c_dlen.value)
            _bytes = bytearray(data)
        else:
            raise IOError('Function can\'t be executed. Error {0}'.format(hex(ret)))

        return _bytes

    def write_raw_meta(self, data):
        """
        This function helps to write the metadata associated with the data object stored on the chip

        :param data:
            Data to write, should be bytearray

        :raises
            - ValueError - when any of the parameters contain an invalid value
            - TypeError - when any of the parameters are of the wrong type
            - OSError - when an error is returned by the chip initialisation library
        """
        api = self.optiga.api

        if not isinstance(data, bytes) and not isinstance(data, bytearray):
            raise TypeError("data should be bytes type")

        if (self.id not in self.optiga.object_id_values) and (self.id not in self.optiga.key_id_values):
            raise TypeError(
                "data_id not found. \n\r Supported = {0} and {1},\n\r  Provided = {2}".format(
                    list(hex(self.optiga.object_id)),
                    list(hex(self.optiga.key_id)),
                    self.id)
            )

        _data = (c_ubyte * len(data))(*data)

        api.exp_optiga_util_write_metadata.argtypes = c_ushort, POINTER(c_ubyte), c_ubyte
        api.exp_optiga_util_write_metadata.restype = c_int

        ret = api.exp_optiga_util_write_metadata(c_ushort(self.id), _data, len(_data))

        if ret != 0:
            raise IOError('Function can\'t be executed. Error {0}'.format(hex(ret)))

        self.updated = True

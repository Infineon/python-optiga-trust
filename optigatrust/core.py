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
import warnings

from optigatrust.const import x, m1, m3, m2id2, charge

__all__ = [
    'Descriptor',
    'Object',
    'handler',
    'random',
    'lifecycle_states',
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

    curr_path = os.path.abspath(os.path.dirname(__file__) + "/csrc/lib/")

    os.chdir(curr_path)
    if os.path.exists(os.path.join(curr_path, libname)):
        api = cdll.LoadLibrary(os.path.join(curr_path, libname))
    else:
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


class Descriptor:
    """
    A class used to represent the whole OPTIGA Trust Chip

    :ivar api: A ctypes descriptor pointing to the right shared library used for the communication
    :vartype api: ctypes.CDDL

    :ivar name: We can't know for sure the right name of the chip, but we can have a good guess based on the firmware id
    :vartype name: str

    """
    def __init__(self, api):
        """
        This class

        :ivar api: A ctypes descriptor pointing to the right shared library used for the communication
        :vartype id: ctypes.CDDL

        return:
            self
        """
        self.api = api
        consts, name = _lookup_optiga(api)
        self.name = name
        self._object_id = consts.ObjectId
        self._object_id_values = set(item.value for item in self._object_id)
        self._key_usage = consts.KeyUsage
        self._key_usage_values = set(item.value for item in self._key_usage)
        self._key_id = consts.KeyId
        self._key_id_values = set(item.value for item in self._key_id)
        self._session_id = consts.SessionId
        self._session_id_values = set(item.value for item in self._session_id)
        self._rng = consts.Rng
        self._rng_values = set(item.value for item in self._rng)
        self._curves = consts.Curves
        self._curves_values = set(item.value for item in self._curves)

    @property
    def current_limit(self):
        """
        This property allows to get or set the current limitation of the chip. Allowed range from 6 to 15 mA
        """
        return int.from_bytes(Object(0xe0c4).read(), "big")

    @current_limit.setter
    def current_limit(self, val: int):
        if val < 6 or val > 15:
            raise ValueError(
                'Current limitation is not supported. Should be between 6 and 15 mA, you have {0}'.format(val)
            )
        Object(0xe0c4).write(bytes([val]))

    @property
    def sleep_activation_delay(self):
        """
        This property allows to get or set the sleep activation delay for your chip
        (time the chip should wait after all operations are finished before going to sleep)
        """
        return int.from_bytes(Object(0xe0c3).read(), "big")

    @sleep_activation_delay.setter
    def sleep_activation_delay(self, val: int):
        if val < 1 or val > 255:
            raise ValueError(
                'Sleep activation value is not supported. Should be between 1 and 255 mA, you have {0}'.format(val)
            )
        Object(0xe0c3).write(bytes([val]))

    @property
    def uid(self):
        """
        This property allows to get a Coprocessor Unique ID. It will be returned as a namedtuple class. Example ::

            UID(cim_id='cd', platform_id='16', model_id='33', rommask_id='9301', chip_type='001c00050000',
                batch_num='0a09a413000a', x_coord='007d', y_coord='003b', fw_id='80101071', fw_build='2440')

        """
        _uid = Object(0xe0c2).read(force=True)
        uid = UID(cim_id=_uid[0:1].hex(),
                  platform_id=_uid[1:2].hex(),
                  model_id=_uid[2:3].hex(),
                  rommask_id=_uid[3:5].hex(),
                  chip_type=_uid[5:11].hex(),
                  batch_num=_uid[11:17].hex(),
                  x_coord=_uid[17:19].hex(),
                  y_coord=_uid[19:21].hex(),
                  fw_id=_uid[21:25].hex(),
                  fw_build=_uid[25:27].hex())
        return uid

    @property
    def global_lifecycle_state(self):
        """
        This property allows to get or set the global lifecycle state for your chip.
        Should be one of core.lifecycle_states
        """
        return lifecycle_states[int.from_bytes(Object(0xe0c0).read(), 'big')]

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
        """
        This property allows to get the security status for your chip.
        """
        return int.from_bytes(Object(0xe0c1).read(), "big")

    @property
    def security_event_counter(self):
        """
        This property allows to get the security event counter for your chip.
        """
        return int.from_bytes(Object(0xe0c5).read(), "big")

    def __str__(self):
        top = "Guessed chip name: {0}\n".format(self.name)
        fw_id = '{0:<30}{1:^10}:{2}\n'.format("Firmware Identifier", "[dwFirmwareIdentifier]", self.uid.fw_id)
        fw_build = '{0:<30}{1:^10}:{2}\n'.format("Build Number", "[rgbESWBuild]", self.uid.fw_build)
        current_limit = '{0:<30}{1:^10}:{2}\n'.format("Current Limitation", "[OID: 0xE0C4]", hex(self.current_limit))
        sleep_delay = '{0:<30}{1:^10}:{2}\n'.format("Sleep Activation Delay", "[OID: 0xE0C3]",
                                                    hex(self.sleep_activation_delay))
        lcsg = '{0:<30}{1:^10}:{2}\n'.format("Global Lifecycle State", "[OID: 0xE0C0]", self.global_lifecycle_state)
        sec_status = '{0:<30}{1:^10}:{2}\n'.format("Security Status", "[OID: 0xE0C1]", hex(self.security_status))
        sec_counter = '{0:<30}{1:^10}:{2}\n'.format("Security Event Counter", "[OID: 0xE0C5]",
                                                    hex(self.security_event_counter))

        return top + fw_id + fw_build + current_limit + sleep_delay + lcsg + sec_status + sec_counter


def handler():
    """
    This function either initialises non-initialised communication channel between the chip and the application, or
    returns an existing communication
    ONLY ONE Optiga Instance is supported

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

        _optiga_descriptor = Descriptor(api)
        print(_optiga_descriptor)

    return _optiga_descriptor


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

    if _fw_build in {0x501, 0x624, 0x751, 0x802, 0x809}:
        return m1, "OPTIGA™ Trust M V1 (SLS32AIA010MH/S)"
    if _fw_build in {0x2440}:
        return m3, "OPTIGA™ Trust M V3 (SLS32AIA010ML/K)"
    elif _fw_build in {0x510, 0x715, 0x1048, 0x1112, 0x1118}:
        return x, "OPTIGA™ Trust X (SLS32AIA020X2/4)"


def random(n, trng=True):
    """
    This function generates a random number

    :ivar n:
        how much randomness to generate. Valid values are from 8 to 256
    :vartype n: int

    :ivar trng:
        If True the a True Random Generator will be used, otherwise Deterministic Random Number Generator
    :vartype trng: bool

    :raises:
        - TypeError - when any of the parameters are of the wrong type
        - OSError - when an error is returned by the chip initialisation library

    :returns:
        Bytes object with randomness
    """
    optiga = handler()
    api = optiga.api

    api.exp_optiga_crypt_random.argtypes = c_byte, POINTER(c_ubyte), c_ushort
    api.exp_optiga_crypt_random.restype = c_int
    p = (c_ubyte * n)()

    if trng is True:
        ret = api.exp_optiga_crypt_random(optiga._rng.TRNG.value, p, len(p))
    else:
        ret = api.exp_optiga_crypt_random(optiga._rng.DRNG.value, p, len(p))

    if ret == 0:
        return bytes(p)
    else:
        return bytes(0)


lifecycle_states = {
    0x01: 'creation',
    0x03: 'initialization',
    0x07: 'operational',
    0x0f: 'termination'
}

_lifecycle_states_swaped = {y: x for x, y in lifecycle_states.items()}

_key_usages = {
    'authentication': 0x01,
    'encryption': 0x02,
    'signature': 0x10,
    'key_agreement': 0x20,
}

_key_usages_swaped = {y: x for x, y in _key_usages.items()}

_meta_tags = {
    'execute': 0xd3,
    'change': 0xd0,
    'read': 0xd1,
    'metadata': 0x20,
    'lcso': 0xc0,
    'version': 0xc1,
    'max_size': 0xc4,
    'used_size': 0xc5,
    'algorithm': 0xe0,
    'key_usage': 0xe1,
    'type': 0xe8,
    'reset_type': 0xf0,
}

_meta_tags_swaped = {y: x for x, y in _meta_tags.items()}

_algorithms = {
    'secp256r1': 0x03,
    'secp384r1': 0x04,
    'secp521r1': 0x05,
    'brainpoolp256r1': 0x13,
    'brainpoolp384r1': 0x15,
    'brainpoolp512r1': 0x16,
    'rsa1024': 0x41,
    'rsa2048': 0x42,
    'aes128': 0x81,
    'aes192': 0x82,
    'aes256': 0x83,
    'sha256': 0xe2
}

_algorithms_swaped = {y: x for x, y in _algorithms.items()}

_access_conditions_ids = {
    'always': 0x00,
    # 2 bytes, e.g. Enable access if boot phase flag in Security Status application is set → 0x10, 0x20
    # Note: SetDataObject with Param = erase&write clears all bits and with Param = write clears all corresponding
    # bits not set to 1 in data to be written
    'sec_sta_g': 0x10,
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
    'conf': 0x20,
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
    'int': 0x21,
    # 3 byte; Value, Reference (Authorization Reference OID)
    # (e.g. Auto → 0x23, 0xF1, 0xD0)
    'auto': 0x23,
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
    'luc': 0x40,
    # 3 byte; Value, Qualifier, Reference
    # (e.g. LcsG < op → 0x70, 0xFC, 0x07)
    'lcsg': 0x70,
    # 2 byte; Value
    # (e.g. Enable access if boot phase flag in Security Status application is set → 0x90, 0x20)
    # Note: SetDataObject with Param = erase&write clears all bits and with Param = write clears all corresponding
    # bits not set to 1 in data to be written
    'sec_sta_a': 0x90,
    # 3 byte; Value, Qualifier, Reference
    # (e.g. LcsA > in → 0xE0, 0xFB, 0x03)
    'lcsa': 0xe0,
    # 3 byte; Value, Qualifier, Reference
    # (e.g. LcsO < op → 0xE1, 0xFC, 0x07)
    'lcso': 0xe1,
    '==': 0xfa,
    '>': 0xfb,
    '<': 0xfc,
    '&&': 0xfd,
    '||': 0xfe,
    'never': 0xff
}

_access_conditions_ids_swaped = {y: x for x, y in _access_conditions_ids.items()}

_data_object_types = {
    # SRM: BSTR. The Byte String data object type is represented by a sequence of bytes, which could be addressed by
    # offset and length.
    'byte_string': 0x00,
    # SRM: UPCTR. The Up-counter data type implements a counter with a current value which could be increased only
    # and a threshold terminating the counter.
    'up_counter': 0x01,
    # SRM: TA. The Trust Anchor data type contains a single X.509 certificate which could be used in various commands
    # requiring a root of trust.
    'trust_anchor': 0x11,
    # SRM: DEVCERT. The Device Identity data type contains a single X.509 certificate or a chain of certificates
    # (TLS, USB-Type C, ...) which was issued to vouch for the cryptographic identity of the end-device.
    'device_cert': 0x12,
    # SRM: PRESSEC. The Pre-shared Secret contains a binary data string which makes up a pre-shared secret for various
    # purposes (FW-decryption, ...).
    'pre_sh_secret': 0x21,
    # SRM: PTFBIND. The Platform Binding contains a binary data string which makes up a pre-shared secret for platform
    # binding (e.g. used for OPTIGA™ Shielded Connection).
    'platform_binding': 0x22,
    # SRM: UPDATESEC. The Protected Update Secret contains a binary data string which makes up a pre-shared secret for
    # confidentiality protected update of data or key objects. The maximum length is limited to 64 bytes, even if the
    # hosting data object has a higher maximum length.
    'update_secret': 0x23,
    # SRM: AUTOREF. The Authorization Reference contains a binary data string which makes up a reference value for
    # verifying an external entity (admin, user, etc.) authorization.
    'authorization_ref': 0x31
}

_data_object_types_swaped = {y: x for x, y in _data_object_types.items()}

_reset_types = {
    # Setting the LcsO of either a key or data object.
    'lcso_to_creation': 0x01,
    'lcso_to_initialisation': 0x02,
    'lcso_to_operational': 0x07,
    'lcso_to_termination': 0x0f,
    # - Flushing of either a key or data object with zero and set the used length of data objects, if present, to 0x0000
    # - If none of the flushing options is set in metadata, then the SetObjectProtected Manifest setting (if present)
    # gets used.
    # - In case of a key object the algorithm associated gets cleared and sets again with successful generation or
    # writing (protected update) a new key.
    'flushing': 0x10,
    # - Overwriting either a key or data object with random values and set the used length of data objects,
    # if present, to 0x0000.
    # - If none of the flushing options is set in metadata, then the SetObjectProtected Manifest setting
    # (if present) gets used.
    # - In case of a key object the algorithm associated gets cleared and sets again with successful generation or
    # writing (protected update) a new key
    'random_data': 0x20
}

_reset_types_swaped = {y: x for x, y in _reset_types.items()}


def _parse_version(tag_size, meta_itr):
    if tag_size == 2:
        value = int((next(meta_itr) << 8) + next(meta_itr))
        is_valid = bool((value >> 15) & 0x01)
        value &= value & 0x7fff
    else:
        raise ValueError(
            'Tag Size for Max or Used Sizes should be either 2 or 1, you have {0}'.format(tag_size)
        )
    return [is_valid, value]


def _parse_access_conditions(tag_size, meta_itr):
    access_conditions = list()
    i = 0
    while i < tag_size:
        _id = next(meta_itr)
        i += 1
        if _id in _access_conditions_ids_swaped:
            # Conf, Int, auto and luc have as the last two bytes a reference to the oid used for the expression
            # it is just another OID from the system
            if _id == _access_conditions_ids['conf'] \
                    or _id == _access_conditions_ids['int'] \
                    or _id == _access_conditions_ids['auto'] \
                    or _id == _access_conditions_ids['luc']:
                access_conditions.append(_access_conditions_ids_swaped[_id])
                access_conditions.append(hex(next(meta_itr)))
                access_conditions.append(hex(next(meta_itr)))
                i += 2
            elif _id == _access_conditions_ids['sec_sta_a'] \
                    or _id == _access_conditions_ids['sec_sta_g']:
                access_conditions.append(_access_conditions_ids_swaped[_id])
                access_conditions.append(hex(next(meta_itr)))
                i += 1
            else:
                access_conditions.append(_access_conditions_ids_swaped[_id])
        # if we didn't meet the number, it should be in the lifecycle states
        elif _id in lifecycle_states:
            access_conditions.append(lifecycle_states[_id])
        else:
            access_conditions.append(hex(_id))
    if tag_size == 1:
        access_conditions = ''.join(access_conditions)

    return access_conditions


def _parse_lifecycle_state(tag_size, meta_itr):
    lcso = next(meta_itr)
    if lcso not in lifecycle_states:
        raise ValueError(
            'Algorithm tag value {0} not found in supported {1}'.format(lcso, lifecycle_states)
        )
    return lifecycle_states[lcso]


def _parse_key_usage(tag_size: int, meta_itr) -> list:
    key_usage_bytes = next(meta_itr)
    tag_data = list()
    if key_usage_bytes & _key_usages['authentication']:
        tag_data.append('authentication')
    if key_usage_bytes & _key_usages['encryption']:
        tag_data.append('encryption')
    if key_usage_bytes & _key_usages['signature']:
        tag_data.append('signature')
    if key_usage_bytes & _key_usages['key_agreement']:
        tag_data.append('key_agreement')

    return tag_data


def _parse_algorithm(tag_size, meta_itr):
    algorithm = next(meta_itr)
    if algorithm not in _algorithms_swaped:
        raise ValueError(
            'Algorithm tag value {0} not found in supported {1}'.format(algorithm, _algorithms_swaped)
        )
    return _algorithms_swaped[algorithm]


def _parse_reset_type(tag_size, meta_itr):
    reset_type = next(meta_itr)
    if reset_type not in _reset_types_swaped:
        raise ValueError(
            'Reset Type tag value {0} not found in supported {1}'.format(reset_type, _reset_types_swaped)
        )
    return _reset_types_swaped[reset_type]


def _parse_type(tag_size, meta_itr):
    object_type = next(meta_itr)
    if object_type not in _data_object_types_swaped:
        raise ValueError(
            'Type tag value {0} not found in supported {1}'.format(object_type, _data_object_types_swaped)
        )
    return _data_object_types_swaped[object_type]


def _parse_used_max_size(tag_size: int, meta_itr) -> int:
    if tag_size == 2:
        value = int((next(meta_itr) << 8) + next(meta_itr))
    elif tag_size == 1:
        value = int(next(meta_itr))
    else:
        raise ValueError(
            'Tag Size for Max or Used Sizes should be either 2 or 1, you have {0}'.format(tag_size)
        )
    return value


_parser_map = {
    'used_size': _parse_used_max_size,
    'max_size': _parse_used_max_size,
    'type': _parse_type,
    'reset_type': _parse_reset_type,
    'algorithm': _parse_algorithm,
    'key_usage': _parse_key_usage,
    'lcso': _parse_lifecycle_state,
    'change': _parse_access_conditions,
    'execute': _parse_access_conditions,
    'read': _parse_access_conditions,
    'version': _parse_version
}


def parse_raw_meta(raw_meta: bytes or bytearray):
    """
    This function should process the given metadata and return it in a human readable form.

    :ivar raw_meta:
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
    if not isinstance(raw_meta, bytes) and not isinstance(raw_meta, bytearray):
        raise TypeError(
            'Metadata (meta) should be in bytes form, you provided {0}'.format(type(raw_meta))
        )
    meta_tuple = tuple(raw_meta)
    meta_itr = iter(meta_tuple)
    # First byte is always 20
    # For instance
    # [ 20,
    #   17,
    #   c0, 01, 01,
    #   c4, 02, 06, c0,
    #   c5, 02, 01, e5',
    #   d0, 01, ff,
    #   d1, 01, 00,
    #   d3, 01, 00,
    #   e8, 01, 12 ]
    # We skip the very first tag, then record the length o the meta data, then go tag by tag (line by line here).
    # Some tags, like lcso or algorithm have a different value which should be interepeted differently
    next(meta_itr)
    meta_size = next(meta_itr)
    if meta_size == 0:
        return None
    if meta_size < 0 or meta_size > 62:
        raise ValueError(
            'Metadata size can\'t be less than zero and more than 64. Ou have {0}'.format(meta_size)
        )
    meta_parsed = dict()
    try:
        while True:
            tag = _meta_tags_swaped[next(meta_itr)]
            tag_size = next(meta_itr)
            if tag_size == 0:
                warnings.warn('Somehow the tag size for {0} was calculated as 0. Skip.'.format(tag))
                return None
            if tag_size < 0:
                raise ValueError(
                    'Metadata size can\'t be less than zero. Ou have {0}'.format(meta_size)
                )
            if tag not in _parser_map:
                raise ValueError(
                    'Parser for your tag [{0}] is not found'.format(tag)
                )
            meta_parsed[tag] = _parser_map[tag](tag_size, meta_itr)
    except StopIteration:
        return meta_parsed


def _prepare_access_conditions(key, value: list) -> list:
    meta = list()
    size = 0
    meta.append(_meta_tags[key])
    # as this is a list, we can find out how many bytes is required in advance
    meta.append(len(value))
    # we would like to skip some of values
    value_iter = iter(value)
    for element in value_iter:
        if element == 'int' or element == 'conf' or element == 'auto' or element == 'luc':
            _meta = [
                _access_conditions_ids[element],
                int(next(value_iter), 16),
                int(next(value_iter), 16),
            ]
        elif element == 'sec_sta_g' or element == 'sec_sta_a':
            _meta = [
                _access_conditions_ids[element],
                int(next(value_iter), 16)
            ]
        elif element in _lifecycle_states_swaped:
            _meta = [_lifecycle_states_swaped[element]]
        elif element not in _access_conditions_ids:
            raise ValueError(
                'Value for Access Condition isn\'t found. '
                'Accepted values {0}, you provided {1}'.format(_access_conditions_ids.keys(), element)
            )
        else:
            _meta = [_access_conditions_ids[element]]
        meta += _meta
        # Update the size (1 comes from the length done at the beggining )
        size += len(_meta)

    return meta


def _prepare_key_usage(key, value) -> int and list:
    key_usage = 0
    # the value should be of type list()
    if not isinstance(value, list):
        raise TypeError(
            'key usage tag should be provided in the form of a list for instance [\'x\', \'y\', \'z\']'
        )
    for i in value:
        if i not in _key_usages:
            raise ValueError(
                'key usage isn\'t supported. Supported values {0}, you provided {1}'.format(_key_usages, i)
            )
        key_usage |= _key_usages[i]

    meta = [
        _meta_tags[key],  # key
        1,  # size
        key_usage  # value
    ]

    return meta


def _prepare_algorithm(key, value) -> list:
    if value not in _algorithms:
        raise ValueError(
            'Value for Algorithm meta tag isn\'t found. '
            'Accepted values {0}, you provided {1}'.format(_algorithms.keys(), value)
        )
    meta = [
        _meta_tags[key],  # key
        1,  # size
        _algorithms[value]  # value
    ]

    return meta


def _prepare_type(key, value) -> list:
    if value not in _data_object_types:
        raise ValueError(
            'Value for Type meta tag isn\'t found. '
            'Accepted values {0}, you provided {1}'.format(_data_object_types.keys(), value)
        )
    meta = [
        _meta_tags[key],  # key
        1,  # size
        _data_object_types[value]  # value
    ]

    return meta


def _prepare_meta_and_size(key, value) -> list:
    # This is how the result should look like
    # key  size  value
    # Used size and max size tags can't be send to the chip, so ignore them with a warning
    if key == 'used_size' or key == 'max_size':
        warnings.warn('The used size tag and max size tag cannot be defined by a user.Skip.')
        return list()
    # Parse each key, and construct a
    elif key == 'type':
        meta = _prepare_type(key, value)
    elif key == 'algorithm':
        meta = _prepare_algorithm(key, value)
    elif key == 'key_usage':
        meta = _prepare_key_usage(key, value)
    # otherwise the value is most likely an access condition expression
    elif isinstance(value, list):
        meta = _prepare_access_conditions(key, value)
    else:
        if value not in _access_conditions_ids:
            raise ValueError(
                'Tag {0} isn\'t supported'.format(value)
            )
        # typical for 'always', 'never'
        meta = [
            _meta_tags[key],  # key
            1,  # size
            _access_conditions_ids[value]  # value
        ]
    return meta


def prepare_raw_meta(new_meta: dict) -> bytearray:
    """
    This function takes as an imput json-like formatted dictionary and translates it to the data to write into the chip

    :ivar new_meta:
        A dictionary (json like formatted) with new metadata; e.g.::

            {
                "lcso": "creation",
                "change": [
                    "lcso",
                    "<",
                    "operational"
                ],
                "execute": "always",
                "algorithm": "secp384r1",
                "key_usage": "0x21"
            }

    :vartype new_meta: dict

    :raises:
        - ValueError - when any of the parameters contain an invalid value
        - TypeError - when any of the parameters are of the wrong type
        - OSError - when an error is returned by the chip initialisation library

    :returns:
        a bytearray with resulting metadata to write into the chip
    """
    meta = list()
    # This is how the result should look like
    # Global tag   size  key[0]  size[0]  value[0]  key[1]  size[1]  value[1]  key[2]  size[2]  value[2]
    # 20           09    C0      01       03        C4      01       8C        C5      01       0A
    meta.append(0x20)
    # first global size, we will update it later on with new keys, sizes and values appended
    meta.append(0)
    # We get as an input a dictionary, which is handy, we go entry by entry and add them correspondingly in the meta
    for key, value in new_meta.items():
        if key not in _meta_tags:
            raise ValueError(
                'Wrong value. Accepted values: {0}, you provided {1}'.format(_meta_tags.keys(), key)
            )
        # here we call a global parser for all known keys, as a result we should get a sequence of bytes which will have
        # key[n], size[n], value[n] prepared based on the given key entry (n)
        _meta = _prepare_meta_and_size(key, value)
        meta += _meta
        # Update the size of the metadata based on the returned value
        meta[1] += len(_meta)

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

        :ivar _id:
            an Object ID which you would like to initialise; e.g. 0xe0e0
        :vartype id: int

        return:
            self
        """
        self.id = _id
        self.optiga = handler()
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

    def read(self, offset=0, force=False) -> bytearray:
        """
        This function helps to read the data stored on the chip

        :ivar offset:
            An optional parameter defining whether you want to read the data with offset
        :vartype offset: int

        :ivar force:
            This is a parameter which can be used to try to read the data even if id can't be somehow finden
        :vartype force: bool

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
            if self.id not in self.optiga._object_id_values:
                raise TypeError(
                    "object_id not found. \n\r Supported = {0},\n\r  "
                    "Provided = {1}".format(list(hex(self.optiga._object_id)), self.id))

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

        :ivar data:
            Data to write
        :vartype data: bytes or bytearray

        :ivar offset:
            An optional parameter defining whether you want to read the data with offset
        :vartype offset: int

        :raises
            - ValueError - when any of the parameters contain an invalid value
            - TypeError - when any of the parameters are of the wrong type
            - OSError - when an error is returned by the chip initialisation library
        """
        api = self.optiga.api

        if not isinstance(data, bytes) and not isinstance(data, bytearray):
            raise TypeError("data should be bytes type")

        if self.id not in self.optiga._object_id_values:
            raise TypeError(
                "object_id not found. \n\r Supported = {0},\n\r  "
                "Provided = {1}".format(list(hex(self.optiga._object_id)), self.id))

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

        if (self.id not in self.optiga._object_id_values) and (self.id not in self.optiga._key_id_values):
            raise TypeError(
                "data_id not found. \n\r Supported = {0} and {1},\n\r  Provided = {2}".format(
                    list(hex(self.optiga._object_id)),
                    list(hex(self.optiga._key_id)),
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

        :ivar data:
            Data to write
        :vartype data: bytes or bytearray

        :raises
            - ValueError - when any of the parameters contain an invalid value
            - TypeError - when any of the parameters are of the wrong type
            - OSError - when an error is returned by the chip initialisation library
        """
        api = self.optiga.api

        if not isinstance(data, bytes) and not isinstance(data, bytearray):
            raise TypeError("data should be bytes type")

        if (self.id not in self.optiga._object_id_values) and (self.id not in self.optiga._key_id_values):
            raise TypeError(
                "data_id not found. \n\r Supported = {0} and {1},\n\r  Provided = {2}".format(
                    list(hex(self.optiga._object_id)),
                    list(hex(self.optiga._key_id)),
                    self.id)
            )

        _data = (c_ubyte * len(data))(*data)

        api.exp_optiga_util_write_metadata.argtypes = c_ushort, POINTER(c_ubyte), c_ubyte
        api.exp_optiga_util_write_metadata.restype = c_int

        ret = api.exp_optiga_util_write_metadata(c_ushort(self.id), _data, len(_data))

        if ret != 0:
            raise IOError('Function can\'t be executed. Error {0}'.format(hex(ret)))

        self.updated = True

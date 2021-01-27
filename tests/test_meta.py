import pytest
from optigatrust.asymmetric import *
from optigatrust.core import *
from optigatrust.cert import *
from optigatrust.transfer import *
import logging

LOGGER = logging.getLogger(__name__)


def test_meta_read_certificate():
    LOGGER.info('Read metatadata of a certificate object')
    obj = Certificate(0xe0e0)
    print(obj.meta)


def test_meta_read_key_meta():
    LOGGER.info('Read metatadata of a key object')
    obj = EccKey(0xe0f0)
    print(obj.meta)
    obj = RsaKey(0xe0fc)
    print(obj.meta)


def test_meta_read_appdata():
    LOGGER.info('Read metatadata of an Application Data object')
    obj = Object(0xf1d0)
    print(obj.meta)


def test_meta_read_all_oids():
    LOGGER.info('Read metatadata of all possible objects')
    print(to_json())


def test_meta_assign_read_ac():
    LOGGER.info('Assign read never access conditions to an object and try to read')
    obj = Object(0xf1d0)
    old_meta = {'read': obj.meta['read']}
    obj.meta = {'read': 'never'}
    with pytest.raises(IOError):
        print(obj.read())

    obj.meta = old_meta


def test_meta_assign_change_ac():
    LOGGER.info('Assign change never access conditions to an object and try to change')
    obj = Object(0xf1d0)
    old_meta = {'change': obj.meta['change']}
    obj.meta = {'change': 'never'}
    with pytest.raises(IOError):
        print(obj.write(b'\x00\x00\x00'))

    obj.meta = old_meta


def test_meta_assign_execute_ac():
    LOGGER.info('Assign execute never access conditions to an object and try to sign data')
    obj = EccKey(0xe0f0)
    old_meta = {'execute': obj.meta['execute']}
    obj.meta = {'execute': 'never'}
    with pytest.raises(IOError):
        print(obj.ecdsa_sign(b'\x00\x00\x00'))

    obj.meta = old_meta


@pytest.mark.parametrize("ki", [
    {'read': 'always'},
    {'change': 'always'},
    {'execute': 'always'},
    {'change': ['sec_sta_g', '20']},
    {'change': ['conf', 'e1', '40']},
    {'read': ['conf', 'e1', '40']},
    {'execute': ['conf', 'e1', '40']},
    {'change': ['conf', 'f1', 'd0', '&&', 'int', 'f1', 'd0']},
    {'change': ['int', 'e1', '40']},
    {'read': ['int', 'e1', '40']},
    {'execute': ['int', 'e1', '40']},
    {'change': ['int', 'e0', 'ef']},
    {'read': ['auto', 'f1', 'd0']},
    {'execute': ['luc', 'e1', '20']},
    {'change': ['lcsg', '<', 'operational']},
    {'change': ['sec_sta_a', '20']},
    {'change': ['lcsa', '<', 'operational']},
    {'change': ['lcso', '<', 'operational']},
    {'change': ['lcso', '==', 'operational']},
    {'change': ['lcso', '>', 'operational']},
    {'change': ['conf', 'f1', 'd0', '||', 'int', 'f1', 'd0']},
    {'read': 'never'},
    {'change': 'never'},
    {'execute': 'never'},
])
def test_meta_assign_complex_ac(ki):
    LOGGER.info('Assign complex access conditions {0} to an object and '
                'try to check whether they were correctly set'.format(ki))
    obj = Object(0xf1d0)
    for key, value in ki:
        old_meta = {key: obj.meta[key]}
        obj.meta = {key: value}
        assert {key: value} == obj.meta
        obj.meta = old_meta


def test_meta_assign_wrong_tag():
    LOGGER.info('Assign a non-existing tag to an object')
    obj = Object(0xf1d0)
    with pytest.raises(ValueError):
        obj.meta = {'write': 'never'}


def test_meta_assign_wrong_tag_value():
    LOGGER.info('Assign a non-existing tag value to an object')
    obj = Object(0xf1d0)
    with pytest.raises(ValueError):
        obj.meta = {'change': 'nie'}


def test_meta_assign_wrong_tag_used_size():
    LOGGER.info('Assign a used_size tag to an object')
    obj = Object(0xf1d0)
    with pytest.raises(ValueError):
        obj.meta = {'used_size': 423}


def test_meta_assign_wrong_tag_max_size():
    LOGGER.info('Assign a max_size tag to an object')
    obj = Object(0xf1d0)
    with pytest.raises(ValueError):
        obj.meta = {'max_size': 1000}


@pytest.mark.parametrize("ki", [
    'byte_string',
    'up_counter',
    'trust_anchor',
    'device_cert',
    'pre_sh_secret',
    'platform_binding',
    'update_secret',
    'azthorization_ref'
])
def test_meta_set_object_type(ki):
    LOGGER.info('Assign a new type to an an object; i.e. {0} and check whether it has been correctly set'.format(ki))
    obj = Object(0xf1d0)
    old_meta = None
    if 'type' in obj.meta:
        old_meta = {'type': obj.meta['type']}
    obj.meta = {'type': ki}

    assert obj.meta['type'] == ki

    if old_meta is not None:
        obj.meta = old_meta

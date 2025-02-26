# SPDX-FileCopyrightText: 2021-2024 Infineon Technologies AG
# SPDX-License-Identifier: MIT

import pytest
from optigatrust import objects, crypto, port


def test_meta_read_certificate():
    obj = objects.X509(0xE0E0)
    print(obj.meta)


def test_meta_read_key_meta():
    obj = objects.ECCKey(0xE0F0)
    print(obj.meta)
    obj = objects.RSAKey(0xE0FC)
    print(obj.meta)


def test_meta_read_appdata():
    obj = objects.AppData(0xF1D0)
    print(obj.meta)


def test_meta_read_all_oids():
    print(port.to_json())


_meta_tags = {
    "execute": 0xD3,
    "change": 0xD0,
    "read": 0xD1,
    "metadata": 0x20,
    "lcso": 0xC0,
    "version": 0xC1,
    "max_size": 0xC4,
    "used_size": 0xC5,
    "algorithm": 0xE0,
    "key_usage": 0xE1,
    "type": 0xE8,
    "reset_type": 0xF0,
}


def test_meta_assign_read_ac():
    obj = objects.AppData(0xF1D0)
    old_meta = {"read": obj.meta["read"]}
    obj.meta = {"read": "never"}
    with pytest.raises(IOError):
        print(obj.read())

    obj.meta = old_meta


def test_meta_assign_change_ac():
    obj = objects.AppData(0xF1D0)
    old_meta = {"change": obj.meta["change"]}
    obj.meta = {"change": "never"}
    with pytest.raises(IOError):
        print(obj.write(b"\x00\x00\x00"))

    obj.meta = old_meta


def test_meta_assign_execute_ac():
    obj = objects.ECCKey(0xE0F0)
    old_meta = {"execute": obj.meta["execute"]}
    obj.meta = {"execute": "never"}
    with pytest.raises(IOError):
        print(crypto.ecdsa_sign(obj, b"\x00\x00\x00"))

    obj.meta = old_meta


def test_meta_check_max_size():
    obj = objects.AppData(0xF1D0)
    assert 140 == obj.meta["max_size"]
    assert 140 == obj.max_size


def test_meta_check_used_size():
    obj = objects.AppData(0xF1D0)
    assert isinstance(obj.meta["used_size"], int)
    assert isinstance(obj.used_size, int)


def test_meta_assign_max_size():
    obj = objects.AppData(0xF1D0)
    with pytest.raises(OSError):
        obj.meta = {"max_size": 100}


def test_meta_assign_used_size():
    obj = objects.AppData(0xF1D0)
    with pytest.raises(OSError):
        obj.meta = {"used_size": 100}


@pytest.mark.parametrize(
    "curve",
    (
        "secp256r1",
        "secp384r1",
        "secp521r1",
        "brainpoolp256r1",
        "brainpoolp384r1",
        "brainpoolp512r1",
    ),
)
def test_meta_check_algorithm_ecc(curve):
    obj = objects.ECCKey(0xE0F1)
    crypto.generate_pair(key_object=obj, curve=curve)
    assert curve == obj.meta["algorithm"]


@pytest.mark.parametrize("key_size", (1024, 2048))
def test_meta_check_algorithm_rsa(key_size):
    obj = objects.RSAKey(0xE0FC)
    crypto.generate_pair(key_object=obj, key_size=key_size)
    assert ("rsa" + str(key_size)) == obj.meta["algorithm"]


def test_meta_check_key_usage_ecc():
    obj = objects.ECCKey(0xE0F1)
    crypto.generate_pair(
        key_object=obj, curve="secp256r1", key_usage=["signature", "authentication"]
    )
    assert ["signature", "authentication"] == obj.meta["key_usage"] or [
        "authentication",
        "signature",
    ] == obj.meta["key_usage"]


def test_meta_check_key_usage_rsa():
    obj = objects.RSAKey(0xE0FC)
    crypto.generate_pair(key_object=obj, key_size=1024, key_usage=["key_agreement", "encryption"])
    assert ["key_agreement", "encryption"] == obj.meta["key_usage"] or [
        "encryption",
        "key_agreement",
    ] == obj.meta["key_usage"]


@pytest.mark.parametrize(
    "obj_type",
    [
        "byte_string",
        "up_counter",
        "trust_anchor",
        "device_cert",
        "pre_sh_secret",
        "platform_binding",
        "update_secret",
        "authorization_ref",
    ],
)
def test_meta_set_object_type(obj_type):
    obj = objects.AppData(0xF1D0)
    old_meta = None
    if "type" in obj.meta:
        old_meta = {"type": obj.meta["type"]}
    obj.meta = {"type": obj_type}

    assert obj.meta["type"] == obj_type

    if old_meta is not None:
        obj.meta = old_meta


@pytest.mark.parametrize(
    "ki",
    [
        {"read": "always"},
        {"change": "always"},
        {"execute": "always"},
        {"change": ["sec_sta_g", "0x20"]},
        {"change": ["conf", "0xe1", "0x40"]},
        {"read": ["conf", "0xe1", "0x40"]},
        {"execute": ["conf", "0xe1", "0x40"]},
        {"change": ["conf", "0xf1", "0xd0", "&&", "int", "0xf1", "0xd0"]},
        {"change": ["int", "0xe1", "0x40"]},
        {"read": ["int", "0xe1", "0x40"]},
        {"execute": ["int", "0xe1", "0x40"]},
        {"change": ["int", "0xe0", "0xef"]},
        {"read": ["auto", "0xf1", "0xd0"]},
        {"execute": ["luc", "0xe1", "0x20"]},
        {"change": ["lcsg", "<", "operational"]},
        {"change": ["sec_sta_a", "0x20"]},
        {"change": ["lcsa", "<", "operational"]},
        {"change": ["lcso", "<", "operational"]},
        {"change": ["lcso", "==", "operational"]},
        {"change": ["lcso", ">", "operational"]},
        {"change": ["conf", "0xf1", "0xd0", "||", "int", "0xf1", "0xd0"]},
        {"read": "never"},
        {"change": "never"},
        {"execute": "never"},
    ],
)
def test_meta_assign_complex_ac(ki):
    obj = objects.AppData(0xF1D0)
    for key, value in ki.items():
        if key not in obj.meta:
            old_meta = {key: "always"}
        else:
            old_meta = {key: obj.meta[key]}
        obj.meta = {key: value}
        assert {key: value} == {key: obj.meta[key]}
        obj.meta = old_meta


def test_meta_assign_wrong_tag():
    obj = objects.AppData(0xF1D0)
    with pytest.raises(ValueError):
        obj.meta = {"write": "never"}


def test_meta_assign_wrong_tag_value():
    obj = objects.AppData(0xF1D0)
    with pytest.raises(ValueError):
        obj.meta = {"change": "nie"}

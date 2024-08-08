# SPDX-FileCopyrightText: 2021-2024 Infineon Technologies AG
# SPDX-License-Identifier: MIT

from optigatrust import port
import json
import os


def test_port_to_json():
    dump = port.to_json()
    json.dumps(dump, indent=4)


def test_port_from_json():
    dump = port.to_json()
    port.from_json(dump)


def test_port_from_json_path():
    dump = port.to_json()
    port.from_json(dump)

    file_name = ".test.json"
    if os.path.exists(file_name):
        os.remove(file_name)

    with open(file_name, "w+", encoding="utf-8") as f:
        f.write(json.dumps(dump, indent=4))

    port.from_json_path(".test.json")


def test_port_to_otc():
    path = ".export"

    try:
        os.mkdir(path)
    except OSError:
        print("Creation of the directory %s failed" % path)
    else:
        print("Successfully created the directory %s " % path)

    port.to_otc(path)

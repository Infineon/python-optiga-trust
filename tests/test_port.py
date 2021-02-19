from optigatrust import port
import json


def test_port_to_json():
    dump = port.to_json()
    json.dumps(dump, indent=4)


def test_port_from_json():
    dump = port.to_json()
    port.from_json(dump)


def test_port_from_json_path():
    dump = port.to_json()
    port.from_json(dump)

    with open('.test.json', 'w+', encoding='utf-8') as f:
        f.write(json.dumps(dump, indent=4))

    port.from_json_path('.test.json')


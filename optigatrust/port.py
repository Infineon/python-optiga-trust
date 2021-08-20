#!/usr/bin/env python
"""This module implements data/metadata import and export functions """
import os
import re
import json
from jinja2 import Environment, FileSystemLoader
import optigatrust as optiga


__all__ = [
    'to_json',
    'from_json',
    'from_json_path',
    'to_otc',
]


def to_json():
    """
    This function will secentially read all metadata from all available OIDs and return a dictionary with all entrie

    :raises:
        - ValueError - when any of the parameters contain an invalid value
        - TypeError - when any of the parameters are of the wrong type
        - OSError - when an error is returned by the chip initialisation library

    :returns:
        a dictionary will all available metadata per object; e.g. ::

            {
                "e0f1":
                {
                    "metadata":'200fc00101d001ffd301ffe00103e10121',
                    "pretty_metadata":
                    {
                        "lcso": "creation",
                        "change": "never",
                        "execute": "never",
                        "algorithm": "secp256r1",
                        "key_usage": ['authentication', 'key_agreement']
                    }
                },
                "e0c2":
                {
                    "metadata":"2009c4011bd001ffd10100",
                    "pretty_metadata":
                    {
                        "max_size": 27,
                        "change": "never",
                        "read": "always"
                    }
                    "data":"cd16338201001c000500000a091b5c0007006200ad801010710809"
                }
            }

    """
    opt = optiga.Chip()
    output = dict()
    # Read metadata from available keys
    for oid in opt.key_id_values:
        # print('Reading: {0}'.format(hex(oid)))
        key = optiga.Object(oid)
        raw_meta = key.read_raw_meta().hex()
        if len(raw_meta) == 0:
            continue
        output[hex(oid)[2:]] = {
            "metadata": raw_meta,
            "pretty_metadata": key.meta
        }
        del key

    for oid in opt.object_id_values:
        # print('Reading: {0}'.format(hex(oid)))
        key = optiga.Object(oid)
        raw_meta = key.read_raw_meta().hex()
        try:
            data = key.read().hex()
        except IOError:
            print('Data in {0} is not readable - skip.'.format(hex(oid)))
            data = ""
        if len(raw_meta) == 0:
            continue
        output[hex(oid)[2:]] = {
            "metadata": raw_meta,
            "pretty_metadata": key.meta,
            "data": data
        }
        del key

    return output


def from_json(data=None):
    """
    This function will take as an input your data and populate the chip with it, whatever is possible

    :param data: JSON string with the dump of the data. Should be a valid dict structure

    .. highlight:: python
    .. code-block:: python

        {
            "e0f1":
            {
                "metadata":'200fc00101d001ffd301ffe00103e10121',
                "pretty_metadata":
                {
                    "lcso": "creation",
                    "change": "never",
                    "execute": "never",
                    "algorithm": "secp256r1",
                    "key_usage": ['authentication', 'key_agreement']
                }
            },
            "e0c2":
            {
                "metadata":"2009c4011bd001ffd10100",
                "pretty_metadata":
                {
                    "max_size": 27,
                    "change": "never",
                    "read": "always"
                }
                "data":"cd16338201001c000500000a091b5c0007006200ad801010710809"
            }
        }

    :raises:
        - ValueError - when any of the parameters contain an invalid value
        - TypeError - when any of the parameters are of the wrong type
        - OSError - when an error is returned by the chip initialisation library
    """
    supermeta = data

    # Iterate through the dictionary and check all keys and values one by one
    for oid, content in supermeta.items():
        # A flag which we use to identify whether metadata should be reverted for data population
        print('Reading {0}'.format(oid))
        metadata_changed = False
        old_meta = {}
        try:
            # Initialize the object with the object ID in the config
            obj = optiga.Object(int(oid, 16))

            # try at first to write down the data, otherwise it wont be possible to do this later (maybe)
            if 'data' in content:
                # Some settings object don#t have change metadata tag, so we can't assume this
                try:
                    old_meta = {'change': obj.meta['change']}
                except KeyError:
                    pass
                obj.meta = {'change': 'always'}
                metadata_changed = True
                obj.write(bytes.fromhex(content['data']))

            # Wtite raw metadata, this would be the fastest way, don't forget to convert hexstring to bytes
            obj.meta = content['pretty_metadata']

        except (OSError, ValueError, TypeError):
            print('Warning. Failed to update {0} metadata. Skipping'.format(oid))
        else:
            if metadata_changed:
                obj.meta = old_meta


def from_json_path(path):
    """
    This function will take as an input your data and populate the chip with it, whatever is possible

    :param path: path to the json file. The content should be formed like the following

    .. highlight:: python
    .. code-block:: python

        {
            "e0f1":
            {
                "metadata":'200fc00101d001ffd301ffe00103e10121',
                "pretty_metadata":
                {
                    "lcso": "creation",
                    "change": "never",
                    "execute": "never",
                    "algorithm": "secp256r1",
                    "key_usage": ['authentication', 'key_agreement']
                }
            },
            "e0c2":
            {
                "metadata":"2009c4011bd001ffd10100",
                "pretty_metadata":
                {
                    "max_size": 27,
                    "change": "never",
                    "read": "always"
                }
                "data":"cd16338201001c000500000a091b5c0007006200ad801010710809"
            }
        }

    :raises:
        - ValueError - when any of the parameters contain an invalid value
        - TypeError - when any of the parameters are of the wrong type
        - OSError - when an error is returned by the chip initialisation library
    """
    with open(path, 'r', encoding='utf8') as file:
        supermeta = json.loads(file.read())

    from_json(supermeta)


def _to_xml(meta):
    """
    This function will sequentially read all metadata from all available OIDs and return an xml compliant string

    :param: meta json formatted metadata

    :raises:
        - ValueError - when any of the parameters contain an invalid value
        - TypeError - when any of the parameters are of the wrong type
        - OSError - when an error is returned by the chip initialisation library

    :returns:
        an xml string
    """
    opt = optiga.Chip()
    path = os.path.dirname(os.path.abspath(__file__))
    template_env = Environment(
        autoescape=False,
        loader=FileSystemLoader(os.path.join(path, 'enums')),
        trim_blocks=False)
    fname = "conf_template.xml"
    new_meta_list = list()
    for key, value in meta.items():
        # some OIDs are not supported by the OTC
        if key in ["f1c1", "e0c2", "e0c0", "e0c1", "e0c5", "e0c6"]:
            continue

        entry = {
            'id': key.upper(),
            'meta': value['metadata'][4:].upper()
        }
        if 'data' in value:
            if 'used_size' in value['pretty_metadata']:
                entry['data'] = value['data']
        new_meta_list.append(entry)
    context = {
        'name': opt.name,
        'param': new_meta_list
    }
    output = template_env.get_template(fname).render(context)

    return output


def to_otc(path):
    """
    This function exports the whole available dump of the chip in the format compatible with
    the OPTIGA Trust Configurator. Two things will be exported. Data in .dat file format from available objects and
    an xml file with metadata stored. The function uses optigatrust/enums/conf_template.xml and add sequentially all objects
    found on the chip. There are exceptions, objects ["f1c1", "e0c2", "e0c0", "e0c1", "e0c5", "e0c6"] are excluded and
    Objects which don't have 'used_size' metatag defined are excluded

    :param: path Path to the folder where to store the resulting data.

    :raises:
        - ValueError - when any of the parameters contain an invalid value
        - TypeError - when any of the parameters are of the wrong type
        - OSError - when an error is returned by the chip initialisation library

    :returns: an xml string according to the template optigatrust/enums/conf_template.xml

    .. highlight:: xml
    .. code-block:: xml

        <objects>
        <!--OPTIGA Objects Metadata and Data-->
            <oid id="E0F0">
                <metadata value="Updated_Tags">C00101D001FFD30100E00103E10101</metadata>
                <data
                    data_from="Infineon"
                    value="Default"
                    type="Plain"
                    chip_individual="false">
                </data>
            </oid>
            ...
        </objects>

    """
    meta = to_json()
    filepath = os.path.normpath(os.path.abspath(os.path.join(path, 'OPTIGA_Trust.xml')))
    # OTC understands only UTF-8, so the file should be encoded in it
    with open(filepath, 'w+', encoding='utf8') as file:
        supermeta = _to_xml(meta)
        file.write(supermeta)

    for key, value in meta.items():
        if 'data' in value:
            if 'used_size' in value['pretty_metadata']:
                formatted_data = re.sub("(.{64})", "\\1\n", value['data'].upper(), 0, re.DOTALL)
                with open('{0}/{1}.dat'.format(path, key.upper()), 'w+', encoding='utf-8') as file:
                    file.write(formatted_data)

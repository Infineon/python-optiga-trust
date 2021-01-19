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
import re
import codecs
from jinja2 import Environment, FileSystemLoader
from optigatrust.core import *


__all__ = [
    'to_json',
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
                    "metadata":"200fc00101d001ffd30100e00103e10101",
                    "pretty_metadata":
                    {
                        "lcso": "creation",
                        "change": "never",
                        "execute": "always",
                        "algorithm": "nistp256r1",
                        "key_usage": "01"
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
    optiga = init()
    output = dict()
    # Read metadata from available keys
    for oid in optiga.key_id_values:
        key = Object(oid)
        raw_meta = key.read_raw_meta().hex()
        if len(raw_meta) == 0:
            continue
        output[hex(oid)[2:]] = {
            "metadata": raw_meta,
            "pretty_metadata": key.meta
        }
        del key

    for oid in optiga.object_id_values:
        key = Object(oid)
        raw_meta = key.read_raw_meta().hex()
        if len(raw_meta) == 0:
            continue
        output[hex(oid)[2:]] = {
            "metadata": raw_meta,
            "pretty_metadata": key.meta,
            "data": key.read().hex()
        }
        del key

    return output


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
    optiga = init()
    path = os.path.dirname(os.path.abspath(__file__))
    template_env = Environment(
        autoescape=False,
        loader=FileSystemLoader(os.path.join(path, 'const')),
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
        'name': optiga.name,
        'param': new_meta_list
    }
    output = template_env.get_template(fname).render(context)

    return output


def to_otc(path):
    """
    This function exports the whole available dump of the chip in the format compatible with
    the OPTIGA Trust Configurator. Two things will be exported. Data in .dat file format from available objects and
    an xml file with metadata stored. The function uses :doc:`const/conf_template.xml` and add seqentially all objects
    found on the chip. There are exceptions, objects ["f1c1", "e0c2", "e0c0", "e0c1", "e0c5", "e0c6"] are excluded and
    Objects which don't have 'used_size' metatag defined are excluded

    :param: path Path to the folder where to store the resulting data.

    :raises:
        - ValueError - when any of the parameters contain an invalid value
        - TypeError - when any of the parameters are of the wrong type
        - OSError - when an error is returned by the chip initialisation library
    :returns:
        an xml string according to the template :doc:`const/conf_template.xml` ::

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
    filepath = os.path.abspath(path + '/' + 'OPTIGA_Trust.xml')
    # OTC understands only UTF-8, so the file should be encoded in it
    with codecs.open(filepath, 'w+', encoding='utf8') as f:
        supermeta = _to_xml(meta)
        f.write(supermeta)

    for key, value in meta.items():
        if 'data' in value:
            if 'used_size' in value['pretty_metadata']:
                formatted_data = re.sub("(.{64})", "\\1\n", value['data'].upper(), 0, re.DOTALL)
                with open('{0}/{1}.dat'.format(path, key.upper()), 'w+') as f:
                    f.write(formatted_data)
#!/usr/bin/env python

# SPDX-FileCopyrightText: 2021-2024 Infineon Technologies AG
# SPDX-License-Identifier: MIT

"""This script implements a user friendly Command Line Interface of the optigatrust module"""

import os
import sys
import ntpath
import json
from ast import literal_eval
import click
import time

# PEM files parser from the AS1 Crypto Library
from asn1crypto import pem

# Functions to comvert back and forth private and public keys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from optigatrust import objects, crypto, port, util
import optigatrust as optiga
import optigatrust.version as optiga_version

logger = util.Logger(name=__name__)


# pylint: disable=missing-class-docstring disable=missing-function-docstring
def command_required_option_from_option(require_name, require_map):
    class CommandOptionRequiredClass(click.Command):
        def invoke(self, ctx):
            require = ctx.params[require_name]
            if require not in require_map:
                raise click.ClickException(
                    "Unexpected value for --'{}': {}".format(require_name, require)
                )
            if ctx.params[require_map[require].lower()] is None:
                raise click.ClickException(
                    "With {}={} must specify option --{}".format(
                        require_name, require, require_map[require]
                    )
                )
            super().invoke(ctx)

    return CommandOptionRequiredClass


# pylint: disable=unused-argument disable=missing-function-docstring
def validate_id(ctx, param, value):
    """
    Check a given id can be initialised as an object

    :param value:
        a given Object ID

    :raises:
        - click.BadParameter - in case the given object id can't be initialised
    """
    try:
        if value is None:
            return None
        obj = optiga.Object(int(value, base=16))
        obj = obj.meta
        return int(value, base=16)
    except (ValueError, TypeError, OSError) as no_object:
        raise click.BadParameter(
            "Object ID doesn't exist. Please align with the Objects map"
        ) from no_object


# pylint: disable=unused-argument disable=missing-function-docstring
def validate_ecc_rsa_id(ctx, param, value):
    """
    Check a given id can be initialised as an RSA or ECC key object

    :param value:
        a given Object ID

    :raises:
        - click.BadParameter - in case the given object id can't be initialised
    """
    if isinstance(value, str):
        id = int(value, base=16)
    elif isinstance(value, int):
        id = value
    else:
        raise click.BadParameter(
            "Object ID doesn't exist. Please align with the format, should be 0x0ef1"
        )

    try:
        obj = objects.ECCKey(id)
        obj = obj.meta
        return id
    except (ValueError, TypeError, OSError):
        try:
            obj = objects.RSAKey(id)
            obj = obj.meta
            return id
        except (ValueError, TypeError, OSError) as no_rsa:
            raise click.BadParameter(
                "Object ID doesn't exist. Please align with the ECC Objects map"
            ) from no_rsa


def validate_extension(filename):
    """
    Check whether a given filename matches expected handlers

    :param filename:
        an path to the file including an extension

    :raises:
        - click.BadParameter - in case the given filename can't be parsed
    """
    split_tup = os.path.splitext(ntpath.basename(filename))
    file_extension = split_tup[1]
    if file_extension not in (".json", ".pem", ".dat"):
        raise click.BadParameter("File extension is not supported. Read --help")


def handle_pem_extension(oid, _input):
    """
    Read a given file and write it into a given object as an X509 certificate

    :param oid:
        an integer value which should point to the correct Object ID

    :param _input:
        an opened file descriptor from where a data should be read, expected content is a PEM formatted certificate

    :raises:
        - click.BadParameter - in case the given filename can't be parsed
    """
    try:
        cert = objects.X509(oid)
        cert.pem = _input.read()
    except (ValueError, TypeError, OSError) as failed_to_init:
        raise click.BadParameter(
            "[{0}]: File Content can't be parsed or written.\n {1}".format(
                _input.name, _input.read()
            )
        ) from failed_to_init


def handle_dat_extension(oid, _input):
    """
    Read a given file and write it into a given object

    :param oid:
        an integer value which should point to the correct Object ID

    :param _input:
        an opened file descriptor from where a data should be read, expected content is 00 01 02 03 04 ...
    """
    obj = optiga.Object(oid)
    try:
        split_buffer = _input.read().split()
        data = bytes([int(i, base=16) for i in split_buffer])
        obj.write(data)
    except (ValueError, TypeError, OSError) as failed_to_write:
        raise click.BadParameter(
            "[{0}]: File Content can't be parsed or written.\n {1}".format(
                _input.name, _input.read()
            )
        ) from failed_to_write


def insert_newlines(string, every=64):
    """
    This function inserts into a given string a newline every given character

    :param string:
        a string which should be changed

    :param every:
        an argument which defines every which character a newline should be put

    :returns:
        a new string with newlines
    """
    lines = []
    for i in range(0, len(string), every):
        lines.append(string[i : i + every])
    return "\n".join(lines)


def process_metadata_file(file):
    """
    This function processes a given exteranlly generated file and extracts data from c structs

    :param file:
        a file descriptor

    :returns:
        manifest, fragments - a byte type and a list of byte- objects with the data to be sent to the chip
    """
    data = file.read()

    # Find manifest + '=' '{'
    manifest_begin = data.split().index("manifest_data[]") + 3
    manifest_end = data.split().index("};")
    manifest_data = data.split()[manifest_begin:manifest_end]

    for num, elem in enumerate(manifest_data):
        manifest_data[num] = int(elem[:-1], base=16)

    _manifest = bytearray(manifest_data)

    _fragments = []
    for i in range(1, 100):
        try:
            fragment_num = "fragment_0{0}[]".format(i)
            fragment_begin = data.split().index(fragment_num) + 3
            fragment_end = data.split().index("};", fragment_begin)
            fragment_data = data.split()[fragment_begin:fragment_end]

            for num, elem in enumerate(fragment_data):
                fragment_data[num] = int(elem[:-1], base=16)

            _fragments.append(bytearray(fragment_data))

        except ValueError:
            return _manifest, _fragments

    return _manifest, _fragments


def reformat_hex_string(input):
    return util.binary_to_hex(bytearray.fromhex(input))


# pylint: disable=missing-function-docstring
@click.group()
@click.version_option(optiga_version.__version__)
def main():
    pass


@main.command("chipinfo", help="Read out the chip information")
@click.option(
    "--interface",
    type=click.Choice(["I2C", "I2C-GPIOD", "UART", "LIBUSB"], case_sensitive=False),
    default=None,
    required=False,
    help="Specify which interface to use for the connection to the OPTIGA™ Trust device",
)
def chip_info(interface):  # noqa: C901
    chip = optiga.Chip(interface)
    chip_uid = chip.uid

    print("========================================================")
    print(
        "CIM Identifier             [bCimIdentifer]: {}".format(
            reformat_hex_string(chip_uid.cim_id)
        )
    )
    print(
        "Platform Identifer   [bPlatformIdentifier]: {}".format(
            reformat_hex_string(chip_uid.platform_id)
        )
    )
    print(
        "Model Identifer         [bModelIdentifier]: {}".format(
            reformat_hex_string(chip_uid.model_id)
        )
    )
    print(
        "ID of ROM mask                  [wROMCode]: {}".format(
            reformat_hex_string(chip_uid.rommask_id)
        )
    )
    print(
        "Chip Type                    [rgbChipType]: {}".format(
            reformat_hex_string(chip_uid.chip_type)
        )
    )
    print(
        "Batch Number              [rgbBatchNumber]: {}".format(
            reformat_hex_string(chip_uid.batch_num)
        )
    )
    print(
        "X-coordinate              [wChipPositionX]: {}".format(
            reformat_hex_string(chip_uid.x_coord)
        )
    )
    print(
        "Y-coordinate              [wChipPositionY]: {}".format(
            reformat_hex_string(chip_uid.y_coord)
        )
    )
    print(
        "Firmware Identifier [dwFirmwareIdentifier]: {}".format(reformat_hex_string(chip_uid.fw_id))
    )
    print(
        "Build Number                 [rgbESWBuild]: {}".format(
            reformat_hex_string(chip_uid.fw_build)
        )
    )

    fw_build = bytearray.fromhex(chip_uid.fw_build)

    print()
    print("Chip software build: ")
    if (fw_build[0] == 0x05) and (fw_build[1] == 0x10):
        print(
            "OPTIGA™ Trust X; Firmware Version: 1.0.510 (Attention: not all features are supported)"
        )
    elif (fw_build[0] == 0x07) and (fw_build[1] == 0x15):
        print(
            "OPTIGA™ Trust X; Firmware Version: 1.1.715 (Attention: not all features are supported)"
        )
    elif (fw_build[0] == 0x10) and (fw_build[1] == 0x48):
        print(
            "OPTIGA™ Trust X; Firmware Version: 1.2.1048 (Attention: not all features are supported)"
        )
    elif (fw_build[0] == 0x11) and (fw_build[1] == 0x12):
        print(
            "OPTIGA™ Trust X; Firmware Version: 1.30.1112 (Attention: not all features are supported)"
        )
    elif (fw_build[0] == 0x11) and (fw_build[1] == 0x18):
        print(
            "OPTIGA™ Trust X; Firmware Version: 1.40.1118 (Attention: not all features are supported)"
        )
    elif (fw_build[0] == 0x08) and (fw_build[1] == 0x09):
        print("OPTIGA™ Trust M rev.1; Firmware Version: 1.30.809")
    elif (fw_build[0] == 0x24) and (fw_build[1] == 0x40):
        print("OPTIGA™ Trust M rev.3; Firmware Version: 3.00.2440")
    elif (fw_build[0] == 0x25) and (fw_build[1] == 0x64):
        print("OPTIGA™ Trust M rev.3; Firmware Version: 3.02.2564")
    else:
        print("Unknown")

    print("========================================================")


# optigatrust object --id 0xe0f0 --read
# optigatrust object --id 0xe0f0 --read --out [file]
# optigatrust object --id 0xe0f0 --read --meta
# optigatrust object --id 0xe0f0 --in [file]
# pylint: disable=redefined-builtin disable=too-many-arguments disable=too-many-locals
# pylint: disable=too-many-branches disable=too-many-statements disable=missing-function-docstring
@main.command("object", help="Manages objects data and metadata")
@click.option(
    "--id",
    "oid",
    type=click.UNPROCESSED,
    callback=validate_id,
    required=False,
    metavar="<0x1234>",
    help="Select an Object ID you would like to use.",
)
@click.option(
    "--lock",
    is_flag=True,
    default=False,
    required=False,
    help="Lock a given Object by changing it Lifecycle State. This action can be reversed only in special cases. See Metadata Update.",
)
@click.option(
    "--unlock",
    is_flag=True,
    default=False,
    required=False,
    help="Unlock a given Object by running a protected update. ",
)
@click.option(
    "--export-otc",
    is_flag=True,
    default=False,
    required=False,
    help="Export data and metadata from all the objects to the OTC supported format.",
)
@click.option(
    "--export-json",
    is_flag=True,
    default=False,
    required=False,
    help="Export data and metadata from all the objects to the JSON format which can be used to re-import the settings.",
)
@click.option(
    "--meta",
    is_flag=True,
    default=False,
    required=False,
    help="Read metadata from a given Object ID",
)
@click.option(
    "--in",
    "inp",
    type=click.File("r"),
    default=None,
    required=False,
    help="""
                    Write data or metadata into a given Object ID.
                    Provide a path to the text based file which stores the required data/metadata
                    There are three file formats accepted as an input: .json, .dat, .pem
                    
                    \b
                    1) .json - for metadata where individual entries presented as a dictionary,
                        as well as whole expressions are possible:
                        {\'change\': \'[\'lsco\', \'<\', \'operational\']\', \'read\': \'always\'}, or
                        {\'change\': \'always\'}, or
                        {\'lsco\': \'initialisation\'} <- Object Lifecycle state might be irreversible
                    2) .dat - file format with hexadecimal string (given as a text); e.g. 00 01 02 03...
                    3) .pem - file format with valid X.509 Certificate 
                    
                    """,  # noqa: W293,W291
)
@click.option(
    "--out",
    type=click.File("w"),
    default=None,
    required=False,
    help="Select the file where the output should be stored",
)
@click.option(
    "--outform",
    type=click.Choice(["PEM", "DER", "C", "DAT"]),
    default=None,
    required=False,
    help="Define which output type to use",
)
@click.option(
    "--interface",
    type=click.Choice(["I2C", "I2C-GPIOD", "UART", "LIBUSB"], case_sensitive=False),
    default=None,
    required=False,
    help="Specify which interface to use for the connection to the OPTIGA™ Trust device",
)
def object_parser(oid, lock, unlock, export_otc, export_json, meta, inp, out, outform, interface):  # noqa: C901
    buffer = ""
    output = out

    chip = optiga.Chip(interface)

    if export_otc:
        click.echo("Warning, export might take a few minutes to complete")
        if oid or lock or meta or inp or outform:
            raise click.BadParameter("with the --export_otc option other options are ignored")

        chip_uid = chip.uid
        unique_path = "{chip}_{uid}_{data}_{time}".format(
            chip=chip.name,
            uid=chip_uid.fw_build + chip_uid.x_coord + chip_uid.y_coord,
            data=time.strftime("%Y%m%d"),
            time=time.strftime("%H%M%S"),
        )
        unique_path = (
            unique_path.replace(" ", "_").replace("(", "").replace(")", "").replace("/", "_")
        )
        try:
            os.mkdir(unique_path)
        except OSError:
            logger.error("Creation of the directory %s failed" % unique_path)
        else:
            logger.info("Starting export to the directory: %s " % unique_path)
        buffer = port.to_otc(unique_path)

        click.echo(message=buffer, file=output)
        click.echo("Export Completed. Now you can open it with the OTC Tool")
        sys.exit(0)
    elif export_json:
        click.echo("Warning, export might take a few minutes to complete")
        if oid or lock or meta or inp or outform:
            raise click.BadParameter("with the --export_otc option other options are ignored")

        chip = optiga.Chip(interface)
        chip_uid = chip.uid
        unique_path = "{chip}_{uid}_{data}_{time}.json".format(
            chip=chip.name,
            uid=chip_uid.fw_build + chip_uid.x_coord + chip_uid.y_coord,
            data=time.strftime("%Y%m%d"),
            time=time.strftime("%H%M%S"),
        )
        unique_path = (
            unique_path.replace(" ", "_").replace("(", "").replace(")", "").replace("/", "_")
        )
        buffer = json.dumps(port.to_json(), indent=4)
        with open(unique_path, "w+") as js:
            js.write(buffer)

        click.echo("Export completed in the file {0}".format(unique_path))
        sys.exit(0)

    # Todo Test lock
    if lock:
        obj = optiga.Object(oid)

        if export_otc or export_json or meta or inp or out or outform:
            raise click.BadParameter("with the --lock option only --id is allowed")

        if click.confirm(
            "Locking might be irreversible, would you like to prepare the object for a \n protected update to be able to revert this?"
        ):
            click.echo(
                "Please use the update-wizard command first to prepare the object for a protected update"
            )
            sys.exit(0)

        if click.confirm(
            "Do you want to lock this object?\n"
            'This action is going to modify the "Change" Object Access Condition as well as '
            "the Lifecycle State of the Object and might be IRREVERSIBLE."
        ):
            try:
                obj.meta = {"change": ["lcso", "<", "operational"], "lcso": "operational"}
                click.echo("New metadata:")
                buffer = json.dumps(obj.meta, indent=4)
                click.echo(message=buffer, file=output)
            except OSError as no_meta:
                raise click.UsageError("Lock is not possible") from no_meta
        sys.exit(0)

    # Todo Test unlock
    if unlock:
        if export_otc or export_json or meta or out or outform:
            raise click.BadParameter("with the --lock option only --id and --in are allowed")

        if click.confirm(
            "Do you want to unlock this object? This will run the protected update procedure. "
            "In case you didn't prepare the object in advance this action will no take any effect\n"
        ):
            try:
                if inp.name != oid:
                    raise click.UsageError(
                        "The given filename should have the same name as the target Object ID; "
                        "e.g. 0xe0e1.txt with the manifest and fragment structures as generated"
                        "by the protected update data set tool"
                    )
                manifest, fragments = process_metadata_file(inp)
                chip.protected_update(manifest, fragments)
            except OSError as not_updated:
                raise click.UsageError("Unlock is not possible") from not_updated
        sys.exit(0)

    # out will be either stdout or a file
    # so if metadata isn't requested we form a valid output for a file
    if meta:
        obj = optiga.Object(oid)
        buffer = json.dumps(obj.meta, indent=4)
        if outform in ("PEM", "DER"):
            raise click.BadParameter("combination of --meta and --outform")
    else:
        if outform is None and oid:
            outform = "DAT"

    if outform == "PEM":
        try:
            cert = objects.X509(oid)
            buffer = cert.pem
        except ValueError as err:
            raise click.BadParameter(
                "PEM is supported only for objects more than 1.5 kBytes. Original error: {0}".format(
                    err
                )
            )
    elif outform == "DER":
        try:
            cert = objects.X509(oid)
            buffer = cert.der
        except ValueError as err:
            raise click.BadParameter(
                "DER is supported only for objects more than 1.5 kBytes. Original error: {0}".format(
                    err
                )
            )
    elif outform == "C":
        obj = optiga.Object(oid)
        if meta is True:
            data = obj.read_raw_meta()
        else:
            data = obj.read()
        buffer = "".join("0x{:02x}, ".format(x) for x in data)
        buffer = "\n".join(buffer[i : i + 96] for i in range(0, len(buffer), 96))

    elif outform == "DAT":
        obj = optiga.Object(oid)
        if meta is True:
            data = obj.read_raw_meta()
        else:
            data = obj.read()
        buffer = "".join("{:02x} ".format(x) for x in data)
        buffer = "\n".join(buffer[i : i + 66] for i in range(0, len(buffer), 66))

    if inp:
        buffer = "Object Updated"
        output = None
        validate_extension(inp.name)
        split_tup = os.path.splitext(ntpath.basename(inp.name))
        file_extension = split_tup[1]
        if file_extension == ".json":
            if oid:
                click.echo("Import is in progress, the --id option is ignored")
            try:
                port.from_json(literal_eval(inp.read()))
            except (ValueError, TypeError, OSError):
                click.BadParameter(
                    "[{0}]: File Content can't be parsed or written.\n {1}".format(
                        inp.name, inp.read()
                    )
                )
        elif file_extension == ".dat":
            handle_dat_extension(oid, inp)
        elif file_extension == ".pem":
            handle_pem_extension(oid, inp)

    click.echo(message=buffer, file=output)


# pylint: disable=too-many-arguments disable=too-many-locals
# pylint: disable=too-many-branches disable=too-many-statements disable=missing-function-docstring
@main.command(
    "update-wizard", help="Guide through the protected update preparation for a specific Object ID"
)
@click.option(
    "--target-id",
    type=click.UNPROCESSED,
    callback=validate_id,
    required=True,
    metavar="<0x1234>",
    help="Select an Object ID you would like to prepare a protected update for",
)
@click.option(
    "--int-id",
    "int_oid",
    type=click.UNPROCESSED,
    callback=validate_id,
    required=True,
    metavar="<0x1234>",
    help=(
        "define Integrity (Int) enabled for the protected update.\n"
        "In layman terms, define an Object ID where a valid X.509 certificate should be stored. \n"
        "This certificate will be then used to verify a signed payload from an incoming object \n"
        "update request from a remote server."
    ),
)
@click.option(
    "--int-file",
    type=click.File("r"),
    default=None,
    required=True,
    help="Provide a valid X.509 certificate encoded as a PEM file (.pem)",
)
def update_wizard(target_id, int_oid, int_file):  # noqa: C901
    # Access Conditions
    conditions = []
    conf_lock = False
    int_lock = False
    zero = False
    protected_update_meta = {}

    # Open the target object
    target_obj = optiga.Object(target_id)

    click.secho(
        "[0/7]: To run the protected data/metadata update, a host MCU needs to send (forward) a manifest and \n"
        "payload (in fragments). This data might be only signed, or signed and encrypted. \n"
        "This wizard helps you to configure the target Object on the Trust M. \n"
        "This configuration should match the settings set during protected payload generation "
        "on the remote server.\n"
        "NB: If your target Object already has an entry in its metadata; e.g. it has a 'reset_type' "
        "already defined\n it is not possible to remove this entry anymore even after during the protected "
        "metadata update",
        fg="green",
    )
    click.secho(
        "[1/7]: Integrity protection selected. Trust Anchor [{0}] is used to verify the signature of \n"
        "the incoming payload during the protected update. If you leave it unlocked it can be modified in "
        "the future.".format(hex(int_oid)),
        fg="green",
    )
    if click.confirm("[Question]: Do you want to lock the {0} Object?".format(hex(int_oid))):
        int_lock = True

    if int_oid:
        # We need to write the given certificate into the object
        int_obj = optiga.Object(int_oid)

        # Read the certificate, but don't add identity tags to it berfore writing back
        split_tup = os.path.splitext(ntpath.basename(int_file.name))
        if len(split_tup) != 2:
            raise click.BadParameter("Bad filename. Exit")

        if split_tup[1] == ".pem":
            file = int_file.read()
            _, _, der_bytes = pem.unarmor(bytes(file, "utf-8"))
            int_obj.write(der_bytes)
            click.secho(
                "[Info]: Certificate {0} in DER Form has been writen into the {1} Object ID".format(
                    int_file.name, hex(int_oid)
                ),
                fg="blue",
            )
            click.secho(file, fg="blue")
        else:
            raise click.BadParameter("only .pem files are supported as an input")
        # Update metadata to allow internally to use this object
        int_obj.meta = {"type": "trust_anchor", "execute": "always"}
        click.secho(
            "[Info]: Object ID {0} has now 'trust_anchor' data type and Execute Access Condition set to 'always'".format(
                hex(int_oid)
            ),
            fg="blue",
        )

        # In case lock is requested advcance the lcso
        if int_lock:
            int_obj.meta = {"change": ["lcso", "<", "operational"]}
            int_obj.meta = {"lcso": "operational"}
            click.secho("[Info]: Object ID {0} has been locked".format(hex(int_oid)), fg="blue")

        conditions.append("int")
        # Convert OID into an integer '0xe0e1' -> e0e1
        # Split the number and add first and second byte to the list
        conditions.append("0x{:02x}".format((int_oid & 0xFF00) >> 8))
        conditions.append("0x{:02x}".format(int_oid & 0x00FF))

    click.secho(
        "[2/7]: Confidentiality protection is when a secret used to encrypt the protected payload prepared on "
        "the remote server. If selected it requires to know the secret so that this wizard can write it on the "
        "chip",
        fg="green",
    )
    if click.confirm("[Question]: Do you want to enable Confidentiality protection?"):
        conditions.append("&&")

        conf_id = click.prompt(
            click.style(
                "3/7]: Please provide an Object ID; e.g. 0xf1d0, where the secret used to decrypt the payload should be stored",
                fg="green",
            ),
            type=click.UNPROCESSED,
            value_proc=validate_id,
        )

        click.secho(
            "[4/7]: Confidentiality protection selected. Data Object [{0}] is used to decrypt the payload of \n"
            "the incoming the protected update request. If you leave it unlocked it can be modified in "
            "the future.".format(hex(conf_id)),
            fg="green",
        )
        if click.confirm("[Question]: Do you want to lock the {0} Object?".format(hex(conf_id))):
            conf_lock = True

        conf_obj = optiga.Object(conf_id)

        click.secho(
            "[5/7]: This step requires from you to provide a file which contains the secret used to "
            "decrypt the payload sent as part of the protected update.\n"
            "It should be a valid secret with the following content written in a text file. Example:"
            "010203040506..cceeff",
            fg="green",
        )
        conf_file = click.prompt("[Question]: Filename:", type=click.File("r"))

        # In case lock is requested advance the lcso
        if conf_lock:
            conf_obj.meta = {"change": ["lcso", "<", "operational"]}
            conf_obj.meta = {"lcso": "operational"}
            click.secho("[Info]: Object ID {0} has been locked".format(hex(conf_id)), fg="blue")

        # Read the shared secret and write it into the object
        handle_dat_extension(conf_id, conf_file)
        click.secho(
            "[Info]: File {0} has been writen into the {1} Object ID".format(
                conf_file.name, hex(conf_id)
            ),
            fg="blue",
        )
        click.secho(conf_file.read(), fg="blue")
        # Update metadata to allow internally to use this object
        conf_obj.meta = {"type": "update_secret", "execute": "always"}
        click.secho(
            "[Info]: Object ID {0} has now 'update_secret' type and Execute Access Condition set to 'always'".format(
                hex(int_oid)
            ),
            fg="blue",
        )

        conditions.append("conf")
        # Convert Confidentiality OID into an integer '0xf1d0' -> f1d0
        # Split the number and add first and second byte to the list
        conditions.append("0x{:02x}".format((conf_id & 0xFF00) >> 8))
        conditions.append("0x{:02x}".format(conf_id & 0x00FF))
    else:
        click.secho("[3/7]: Skipped.", fg="green")
        click.secho("[4/7]: Skipped.", fg="green")
        click.secho("[5/7]: Skipped.", fg="green")

    click.secho("[6/7]: You need to select what should be updated.", fg="green")
    choice = click.prompt("[Question]: Type 1 for data, 2 for metadata, or 3 for both")

    if choice not in ("1", "2", "3"):
        raise click.BadParameter(
            "[6/7]: you need to select either 1 for data, 2 for metadata or 3 for both"
        )

    if choice in ("2", "3"):
        click.secho(
            "[7/7]: Metadata update is selected. During metadata update it is possibly to flush the content of the object.",
            fg="green",
        )
        zero = click.confirm(
            "[Question]: Do you want to flush {0} Object after the metadata update?".format(
                hex(target_id)
            )
        )

    if choice in ("2", "3"):
        if zero:
            protected_update_meta = {
                "meta_update": conditions,
                "reset_type": ["lcso_to_creation", "flushing"],
            }
        else:
            protected_update_meta = {"meta_update": conditions}

    if choice in ("1", "3"):
        change_ac = target_obj.meta["change"]
        change_ac.append("||")
        change_ac += conditions
        protected_update_meta = {"change": change_ac}

    try:
        target_obj.meta = protected_update_meta
        click.secho(
            "[Info]: target Object ID {0} has now the following metadata:".format(hex(target_id)),
            fg="blue",
        )
        dump = json.dumps(target_obj.meta, indent=4)
        click.secho(dump, fg="blue")
    except OSError:
        click.secho(
            "It is likely that you have exceeded the 44 bytes limit for the metadata. "
            "Existing rules consume {0} bytes. "
            "Try at first to reduce some rules using the 'object' command.".format(
                len(target_obj.read_raw_meta())
            ),
            fg="red",
        )


# Todo: add key and data update as well
# pylint: disable=too-many-arguments disable=too-many-locals
# pylint: disable=too-many-branches disable=too-many-statements disable=missing-function-docstring
@main.command("update", help="Use protected update feature")
@click.option(
    "--id",
    "oid",
    type=click.UNPROCESSED,
    callback=validate_id,
    required=False,
    metavar="<0x1234>",
    help="Select an Object ID you would like to use",
)
@click.option(
    "--file",
    type=click.File("r"),
    default=None,
    required=False,
    help="Provide a valid manifest + fragments file generated by the protected update data set tool",
)
@click.option(
    "--interface",
    type=click.Choice(["I2C", "I2C-GPIOD", "UART", "LIBUSB"], case_sensitive=False),
    default=None,
    required=False,
    help="Specify which interface to use for the connection to the OPTIGA™ Trust device",
)
def update_parser(oid, file, interface):
    if oid != int(os.path.splitext(ntpath.basename(file.name))[0], base=16):
        raise click.BadParameter(
            "used id should be equal to the filename used for the protected update. Moreover the "
            "manifest inside it is coupled with the given id and can't be taken from another file"
        )
    manifest, fragments = process_metadata_file(file)
    try:
        chip = optiga.Chip(interface)
        chip.protected_update(manifest, fragments)
        click.echo("{0} Updated successfully".format(hex(oid)))
        try:
            obj = optiga.Object(oid)
            click.echo("Pretty metadata:")
            click.echo(json.dumps(obj.meta, indent=4))
            click.echo("Data:")
            click.echo("".join("{:02x} ".format(x) for x in obj.read()))
        except OSError:
            pass
    except OSError as not_updated:
        raise ValueError("{0} Update failed".format(hex(oid))) from not_updated


# optigatrust create-keys --out [file]
# optigatrust create-keys --id 0xe0f0 --out [file]
# optigatrust create-keys --id 0xe0f0 --key_usage key_agreement --key_usage signature --out [file]
# optigatrust create-keys --id 0xe0f0 --curve secp256r1 --out [file]
# optigatrust create-keys --id 0xe0f0 --rsa --out [file]
# optigatrust create-keys --id 0xe0f0 --rsa --key_size 1024|2048 --out [file]
# pylint: disable=too-many-arguments disable=too-many-locals
# pylint: disable=too-many-branches disable=too-many-statements disable=missing-function-docstring
@main.command("create-keys", help="Generate a keypair")
@click.option(
    "--id",
    "oid",
    type=click.UNPROCESSED,
    callback=validate_ecc_rsa_id,
    prompt=True,
    default="0xe0f1",
    show_default=True,
    required=True,
    metavar="<0x1234>",
    help="Select an Object ID you would like to use.",
)
@click.option(
    "--rsa",
    is_flag=True,
    default=False,
    show_default=True,
    required=False,
    help="If selected an RSA key generation will be invoked",
)
@click.option(
    "--curve",
    type=click.Choice(
        [
            "secp256r1",
            "secp384r1",
            "secp521r1",
            "brainpoolp256r1",
            "brainpoolp384r1",
            "brainpoolp512r1",
        ]
    ),
    default="secp256r1",
    required=False,
    help="Used during a key generation to define which curve to use",
)
@click.option(
    "--key_usage",
    type=click.Choice(["key_agreement", "authentication", "encryption", "signature"]),
    default=["signature"],
    required=False,
    multiple=True,
    help="Define how the key should be used on the secure element",
)
@click.option(
    "--key_size",
    type=click.Choice(["1024", "2048"]),
    default="1024",
    required=False,
    help="In case the --rsa option is defined it defines the key size in bits",
)
@click.option(
    "--pubout",
    type=click.File("w"),
    default=None,
    required=False,
    help="Select the file where the public key should be stored.",
)
@click.option(
    "--privout",
    type=click.File("w"),
    default=None,
    required=False,
    help="Select the file where the private key should be stored. In this case --id is ignored",
)
@click.option(
    "--interface",
    type=click.Choice(["I2C", "I2C-GPIOD", "UART", "LIBUSB"], case_sensitive=False),
    default=None,
    required=False,
    help="Specify which interface to use for the connection to the OPTIGA™ Trust device",
)
def create_keys(oid, rsa, curve, key_usage, key_size, pubout, privout, interface):
    export = False

    optiga.Chip(interface)

    if rsa:
        obj = objects.RSAKey(oid)
        curve = None
    else:
        obj = objects.ECCKey(oid)
        key_size = "1024"

    if privout is not None:
        export = True

    public_key, private_key = crypto.generate_pair(
        key_object=obj, curve=curve, key_size=int(key_size), key_usage=key_usage, export=export
    )
    parsed_public_key = serialization.load_der_public_key(public_key, backend=default_backend())
    buffer = parsed_public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    click.echo(message=buffer, file=pubout)

    if private_key is not None:
        if rsa:
            click.echo(
                "No PEM output for the RSA Private Key possible. See https://github.com/Infineon/optiga-trust-m/wiki/Data-format-examples#RSA-Private-Key"
            )
            private_buffer = "".join("{:02x} ".format(x) for x in private_key)
        else:
            parsed_private_key = serialization.load_der_private_key(
                private_key, password=None, backend=default_backend()
            )
            private_buffer = parsed_private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        click.echo(message=private_buffer, file=privout)
        if privout is not None:
            click.echo("Generation completed")

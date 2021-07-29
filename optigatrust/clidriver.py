# ============================================================================
# The MIT License
#
# Copyright (c) 2021 Infineon Technologies AG
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
import click
import optigatrust.version as optiga_version
import optigatrust as optiga
import json
from optigatrust import objects, crypto
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


def command_required_option_from_option(require_name, require_map):

    class CommandOptionRequiredClass(click.Command):

        def invoke(self, ctx):
            require = ctx.params[require_name]
            if require not in require_map:
                raise click.ClickException(
                    "Unexpected value for --'{}': {}".format(
                        require_name, require))
            if ctx.params[require_map[require].lower()] is None:
                raise click.ClickException(
                    "With {}={} must specify option --{}".format(
                        require_name, require, require_map[require]))
            super(CommandOptionRequiredClass, self).invoke(ctx)

    return CommandOptionRequiredClass


@click.group(chain=True)
@click.version_option(optiga_version.__version__)
@click.pass_context
def main(ctx):
    pass


def validate_id(ctx, param, value):
    try:
        obj = optiga.Object(int(value, base=16))
        obj = obj.meta
        return int(value, base=16)
    except (ValueError, TypeError, OSError):
        raise click.BadParameter("Object ID doesn't exist. Please align with the Objects map")


def validate_ecc_id(ctx, param, value):
    try:
        obj = objects.ECCKey(int(value, base=16))
        obj = obj.meta
        return int(value, base=16)
    except (ValueError, TypeError, OSError):
        raise click.BadParameter("Object ID doesn't exist. Please align with the ECC Objects map")


def validate_extension(filename):
    split_tup = os.path.splitext(filename)
    file_extension = split_tup[1]
    if file_extension not in ('.json', '.pem', '.dat'):
        raise click.BadParameter('File extension is not supported. Read --help')


def handle_pem_extension(oid, _input):
    try:
        cert = objects.X509(oid)
        cert.pem = _input.read()
    except (ValueError, TypeError, OSError):
        click.BadParameter(
            '[{0}]: File Content can\'t be parsed or written.\n {1}'.format(_input.name, _input.read())
        )


def handle_dat_extension(obj, _input):
    try:
        split_buffer = _input.read().split()
        data = bytes([int(i, base=16) for i in split_buffer])
        obj.write(data)
    except (ValueError, TypeError, OSError):
        click.BadParameter(
            '[{0}]: File Content can\'t be parsed or written.\n {1}'.format(_input.name, _input.read())
        )


def insert_newlines(string, every=64):
    lines = []
    for i in range(0, len(string), every):
        lines.append(string[i:i+every])
    return '\n'.join(lines)


# optigatrust object --id 0xe0f0 --read
# optigatrust object --id 0xe0f0 --read --out [file]
# optigatrust object --id 0xe0f0 --read --meta
# optigatrust object --id 0xe0f0 --write [file]
@main.command('object', help='Manages objects data and metadata')
@click.pass_context
@click.option('--id', 'oid', type=click.UNPROCESSED, callback=validate_id, prompt=True,
              default='0xe0e0', show_default=True, required=True,
              metavar='<0x1234>',
              help='Select an Object ID you would like to use. Use 0xffff to read all')
@click.option('--meta', is_flag=True,
              default=None, required=False,
              help='Read metadata from a given Object ID')
@click.option('--in', '-i', 'inp', type=click.File('r'),
              default=None, required=False,
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
                    
                    """
              )
@click.option('--out', type=click.File('w'),
              default=None, required=False,
              help='Select the file where the output should be stored')
@click.option('--outform', type=click.Choice(['PEM', 'DER', 'C', 'RAW']),
              default='RAW', required=True,
              help='Define which output type to use')
def objects_parser(ctx, oid, meta, inp, out, outform):
    obj = optiga.Object(oid)
    buffer = ''
    output = out

    # out will be either stdout or a file
    # so if metadata isn't requested we form a valid output for a file
    if meta:
        buffer = json.dumps(obj.meta, indent=4)
    elif outform == 'PEM':
        cert = objects.X509(oid)
        buffer = cert.pem
    elif outform == 'DER':
        cert = objects.X509(oid)
        buffer = cert.der
    elif outform == 'C':
        buffer = ''.join('0x{:02x}, '.format(x) for x in obj.read())
        buffer = '\n'.join(buffer[i:i + 96] for i in range(0, len(buffer), 96))
    elif outform == 'RAW':
        buffer = ''.join('{:02x} '.format(x) for x in obj.read())
        buffer = '\n'.join(buffer[i:i + 66] for i in range(0, len(buffer), 66))

    if inp:
        buffer = 'Object Updated'
        output = None
        validate_extension(inp.name)
        split_tup = os.path.splitext(inp.name)
        file_extension = split_tup[1]
        if file_extension == '.json':
            try:
                obj.meta = inp.read()
            except (ValueError, TypeError, OSError):
                click.BadParameter(
                    '[{0}]: File Content can\'t be parsed or written.\n {1}'.format(inp.name, inp.read())
                )
        elif file_extension == '.dat':
            handle_dat_extension(obj, inp)
        elif file_extension == '.pem':
            handle_pem_extension(oid, inp)

    click.echo(message=buffer, file=output)


# optigatrust create-keys --out [file]
# optigatrust create-keys --id 0xe0f0 --out [file]
# optigatrust create-keys --id 0xe0f0 --key_usage key_agreement --key_usage signature --out [file]
# optigatrust create-keys --id 0xe0f0 --curve secp256r1 --out [file]
# optigatrust create-keys --id 0xe0f0 --rsa --out [file]
# optigatrust create-keys --id 0xe0f0 --rsa --key_size 1024|2048 --out [file]
@main.command('create-keys', help='Generate a keypair')
@click.pass_context
@click.option('--id', 'oid', type=click.UNPROCESSED, callback=validate_ecc_id, prompt=True,
              default='0xe0e0', show_default=True, required=True,
              metavar='<0x1234>',
              help='Select an Object ID you would like to use. Use 0xffff to read all')
@click.option('--rsa', is_flag=True,
              default=False, show_default=True, required=True,
              help='If selected an RSA key generation will be invoked')
@click.option('--curve', type=click.Choice(['secp256r1', 'secp384r1', 'secp512r1',
                                            'brainpool256r1', 'brainpool384r1', 'brainpool521r1']),
              default='secp256r1', required=True,
              help='Used during a key generation to define which curve to use')
@click.option('--key_usage', type=click.Choice(['key_agreement', 'authentication', 'encryption', 'signature']),
              default=['signature'], required=True, multiple=True,
              help='Define how the key should be used on the secure element')
@click.option('--key_size', type=click.Choice(['1024', '2048']),
              default='1024', required=True,
              help='In case the --rsa option is defined it defines the key size in bits')
@click.option('--pubout', type=click.File('w'),
              default=None, required=False,
              help='Select the file where the public key should be stored.')
@click.option('--privout', type=click.File('w'),
              default=None, required=False,
              help='Select the file where the private key should be stored. In this case --id is ignored')
def ec_parser(ctx, oid, rsa, curve, key_usage, key_size, pubout, privout):
    export = False

    if rsa:
        obj = objects.RSAKey(oid)
        curve = None
    else:
        obj = objects.ECCKey(oid)
        key_size = None

    if privout is not None:
        export = True

    public_key, private_key = crypto.generate_pair(key_object=obj, curve=curve,
                                                   key_size=key_size, key_usage=key_usage, export=export)
    parsed_public_key = serialization.load_der_public_key(public_key, backend=default_backend())
    buffer = parsed_public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    click.echo(message=buffer, file=pubout)

    if private_key is not None:
        parsed_private_key = serialization.load_der_private_key(private_key, password=None, backend=default_backend())
        private_buffer = parsed_private_key.private_bytes(serialization.Encoding.PEM,
                                                          serialization.PrivateFormat.PKCS8,
                                                          serialization.NoEncryption())
        click.echo(message=private_buffer, file=privout)
        if privout is not None:
            click.echo('Generation completed')




# optigatrust rsa --id 0xe0fc --sign [file]
# optigatrust rsa --genkey --out [file]
# optigatrust rsa --id 0xe0f0 --genkey --out [file]
# optigatrust rsa --id 0xe0f0 --genkey --key_size 1024 --out [file]
@main.command('rsa', help='Do RSA related operations using the OPTIGA Trust M')
@click.option('--id', 'oid', type=click.UNPROCESSED, callback=validate_id, prompt=True,
              default='0xe0e0', show_default=True, required=True,
              help='Select an Object ID you would like to use. Use 0xffff to read all')
@click.option('--genkey', '-g', is_flag=True,
              default=None, required=False,
              help='Generate a new keypair either in a given Object ID or export it')
@click.option('--sign', type=click.Path(exists=True),
              is_flag=True,
              default=None, required=False,
              help='Sign data using a given Object ID')
@click.option('--key_size', type=click.Choice(['1024', '2048']),
              default=None, required=False,
              help='Select which key_size should be used for the key pair generation')
@click.option('--out', type=click.File('w'),
              default=None, required=False,
              help='Select the file where the output should be stored')
def rsa_parser(ctx, oid, genkey, sign, key_size, out):
    pass


# optigatrust kdf --id 0xf1d0
# optigatrust kdf --id 0xf1d0 --key_size 64
# optigatrust kdf --id 0xf1d0 --key_size 64 --seed [file]
# optigatrust kdf --id 0xf1d0 --key_size 64 --seed [file] --hash [sha256, sha384, sha512]
# optigatrust kdf --id 0xf1d0 --key_size 64 --seed [file] --hash [sha256, sha384, sha512] --out [file]
@main.command('kdf', help='Do Key Derivation using the OPTIGA Trust M')
@click.option('--id', 'oid', type=click.UNPROCESSED, callback=validate_id, prompt=True,
              default='0xe0e0', show_default=True, required=True,
              help='Select an Object ID you would like to use. Use 0xffff to read all')
@click.option('--key_size', type=click.Choice(['1024', '2048']),
              default=None, required=False,
              help='Select which key_size should be used for the key pair generation')
@click.option('--seed', '-g', type=click.Path(exists=True),
              default=None, required=False,
              help='Generate a new keypair either in a given Object ID or export it')
@click.option('--hash', 'hs', type=click.Choice(['sha256', 'sha384', 'sha512']),
              default=None, required=False,
              help='Use a dedicated hash algorithm')
@click.option('--out', type=click.File('w'),
              default=None, required=False,
              help='Select the file where the output should be stored')
def kdf_parser(ctx, oid, key_size, seed, hs, out):
    pass

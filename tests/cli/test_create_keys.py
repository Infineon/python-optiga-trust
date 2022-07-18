import pytest
from click.testing import CliRunner
from optigatrust.clidriver import object_parser


# optigatrust create-keys --id 0xe0f1
# optigatrust create-keys --id 0xe0f1 --privout [file]
# optigatrust create-keys --id 0xe0f1 --curve
@pytest.mark.parametrize("stimulus, expected_result", [
    ('--id 0xe0f1 --curve secp256r1', 0),
    ('--id 0xe0f2 --curve secp384r1', 0),
    ('--id 0xe0f3 --curve secp521r1', 0),
    ('--id 0xe0f1 --curve brainpoolp256r1', 0),
    ('--id 0xe0f2 --curve brainpoolp384r1', 0),
    ('--id 0xe0f3 --curve brainpoolp512r1', 0),
    ('--id 0xe0fc --rsa', 0),
    ('--id 0xe0f9 --rsa --key_size 2048', 0),
    ('--id 0xe0fc --rsa --key_size 2024', 2),
    ('--id 0xe0ff', 2),
    ('--id 0xe0f1 --curve sec256r1', 2),
    ('--id 0xe0O0', 2),
    ('--id 0xe0f1 --curve secp256r1 --key_usage authentication', 0),
    ('--id 0xe0f2 --curve secp256r1 --key_usage key_agreement', 0),
    ('--id 0xe0f3 --curve secp256r1 --key_usage encryption', 0),
    ('--id 0xe0f1 --curve secp256r1 --key_usage signature', 0),
    ('--id 0xe0f2 --curve secp256r1 --key_usage signature --key_usage authentication', 0),
    ('--id 0xe0f1 --curve secp256r1 --key_usage sinature', 2),
    ('--id 0xe0f1 --curve secp256r1 --pubout test.pkey', 0),
    ('--id 0xe0f2 --curve secp256r1 --pubout test.pkey --privout test.key', 0),
])
def test_create_keys(stimulus, expected_result):
    runner = CliRunner()
    test = stimulus.split(' ')

    with runner.isolated_filesystem():
        result = runner.invoke(object_parser, test, terminal_width=100)
        assert result.exit_code == expected_result

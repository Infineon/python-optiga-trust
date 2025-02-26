# SPDX-FileCopyrightText: 2021-2024 Infineon Technologies AG
# SPDX-License-Identifier: MIT

import pytest
import json
import re
from click.testing import CliRunner
from optigatrust.clidriver import object_parser


# optigatrust object --id 0xe0f0
# optigatrust object --id 0xe0f0 --out [file]
# optigatrust object --id 0xe0f0 --meta
@pytest.mark.parametrize(
    "stimulus, expected_result",
    [
        ("--id 0xe0e0", 0),
        ("--id 0xe000", 2),
        ("--id e000", 2),
        ("--id 0xe0O0", 2),
        ("--id 0xe0f0", 1),
        ("--id 0xe0e0 --meta", 0),
        ("--id 0xe0e0 --outform C", 0),
        ("--id 0xe0e0 --outform DAT", 0),
        ("--id 0xe0e0 --outform PEM", 0),
        ("--id 0xe0e0 --outform DER", 0),
        ("--id 0xf1d0 --outform PEM", 2),
        ("--id 0xf1d0 --outform DER", 2),
        ("--id 0xe0e0 --outform der", 2),
        ("--id 0xe0e0 --outform dr", 2),
        ("--id 0xe0e0 --out e0e0_data.c --outform C", 0),
        ("--id 0xe0e0 --out e0e0_data.pem --outform PEM", 0),
        ("--id 0xe0e0 --out e0e0_data.der --outform DER", 0),
        ("--id 0xe0e0 --meta --outform C", 0),
        ("--id 0xe0e0 --meta --outform DAT", 0),
        ("--id 0xe0e0 --meta --outform PEM", 2),
        ("--id 0xe0e0 --meta --outform DER", 2),
        ("--id 0xe0e0 --meta --out e0e0_meta.dat --outform DAT", 0),
        ("--id 0xe0e0 --meta --out e0e0_meta.dat --outform PEM", 2),
        ("--id 0xe0e0 --meta --out e0e0_meta.dat --outform DER", 2),
        ("--id 0xe0e0 --meta --out e0e0_meta.dat", 0),
    ],
)
def test_object(stimulus, expected_result):
    runner = CliRunner()
    test = stimulus.split(" ")

    with runner.isolated_filesystem():
        result = runner.invoke(object_parser, test, terminal_width=100)
        assert result.exit_code == expected_result


def test_metadata_json_output():
    runner = CliRunner()
    result = runner.invoke(object_parser, ["--id", "0xe0e0", "--meta"], terminal_width=100)
    # Loaded: liboptigatrust-uart-win-i686.dll
    output = re.sub("Loaded: liboptigatrust.*dll", "", result.output)
    assert result.exit_code == 0
    assert json.loads(output)


def test_metadata_json_output_in_file():
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(
            object_parser,
            ["--id", "0xe0e0", "--meta", "--out", "e0e0_meta.json"],
            terminal_width=100,
        )
        assert result.exit_code == 0
        with open("e0e0_meta.json", "r") as f:
            assert json.loads(f.read())


def test_object_with_input():
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(
            object_parser,
            ["--id", "0xe0e0", "--meta", "--out", "e0e0_meta.json"],
            terminal_width=100,
        )
        assert result.exit_code == 0
        with open("e0e0_meta.json", "r") as f:
            assert json.loads(f.read())

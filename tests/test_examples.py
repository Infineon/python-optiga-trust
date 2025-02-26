# SPDX-FileCopyrightText: 2021-2024 Infineon Technologies AG
# SPDX-License-Identifier: MIT

import pytest


@pytest.mark.script_launch_mode("inprocess")
def test_example_ecc_key_generation(script_runner):
    script_runner.run("examples/ecc_key_generation.py", print_result=True, check=True)


@pytest.mark.script_launch_mode("inprocess")
def test_example_ecdsa_signverify(script_runner):
    script_runner.run("examples/ecdsa_signverify.py", print_result=True, check=True)


@pytest.mark.script_launch_mode("inprocess")
def test_example_ecdsa_signverify_oid(script_runner):
    script_runner.run("examples/ecdsa_signverify_oid.py", print_result=True, check=True)


@pytest.mark.script_launch_mode("inprocess")
def test_example_ecdsa_verify_sw(script_runner):
    script_runner.run("examples/ecdsa_verify_sw.py", print_result=True, check=True)


@pytest.mark.script_launch_mode("inprocess")
def test_example_ecdsa_verify(script_runner):
    script_runner.run("examples/ecdsa_verify.py", print_result=True, check=True)

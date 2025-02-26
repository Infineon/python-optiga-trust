# SPDX-FileCopyrightText: 2025 Infineon Technologies AG
# SPDX-License-Identifier: MIT

"""Read Chip information from OPTIGA™ Trust device

This example shows how to read out chip information from an OPTIGA™ Trust device.
"""

# Uncomment to use the local version (source) of this library instead of the pip package
# import sys, os
# sys.path.append(os.path.join(os.path.dirname(__file__), ".." , "src"))

import optigatrust as optiga
from optigatrust import util


def reformat_hex_string(input):
    return util.binary_to_hex(bytearray.fromhex(input))


chip_handler = optiga.Chip()
chip_uid = chip_handler.uid

print("========================================================")
print("CIM Identifier             [bCimIdentifer]: {}".format(reformat_hex_string(chip_uid.cim_id)))
print(
    "Platform Identifer   [bPlatformIdentifier]: {}".format(
        reformat_hex_string(chip_uid.platform_id)
    )
)
print(
    "Model Identifer         [bModelIdentifier]: {}".format(reformat_hex_string(chip_uid.model_id))
)
print(
    "ID of ROM mask                  [wROMCode]: {}".format(
        reformat_hex_string(chip_uid.rommask_id)
    )
)
print(
    "Chip Type                    [rgbChipType]: {}".format(reformat_hex_string(chip_uid.chip_type))
)
print(
    "Batch Number              [rgbBatchNumber]: {}".format(reformat_hex_string(chip_uid.batch_num))
)
print(
    "X-coordinate              [wChipPositionX]: {}".format(reformat_hex_string(chip_uid.x_coord))
)
print(
    "Y-coordinate              [wChipPositionY]: {}".format(reformat_hex_string(chip_uid.y_coord))
)
print("Firmware Identifier [dwFirmwareIdentifier]: {}".format(reformat_hex_string(chip_uid.fw_id)))
print(
    "Build Number                 [rgbESWBuild]: {}".format(reformat_hex_string(chip_uid.fw_build))
)

fw_build = bytearray.fromhex(chip_uid.fw_build)

print()
print("Chip software build: ")
if (fw_build[0] == 0x05) and (fw_build[1] == 0x10):
    print("OPTIGA™ Trust X; Firmware Version: 1.0.510 (Attention: not all features are supported)")
elif (fw_build[0] == 0x07) and (fw_build[1] == 0x15):
    print("OPTIGA™ Trust X; Firmware Version: 1.1.715 (Attention: not all features are supported)")
elif (fw_build[0] == 0x10) and (fw_build[1] == 0x48):
    print("OPTIGA™ Trust X; Firmware Version: 1.2.1048 (Attention: not all features are supported)")
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
elif (fw_build[0] == 0x25) and (fw_build[1] == 64):
    print("OPTIGA™ Trust M rev.3; Firmware Version: 3.02.2564")
else:
    print("Unknown")

print("========================================================")

import os
from pathlib import Path
from struct import pack, unpack
from typing import Dict, List
from rich import print
import zlib
import configparser

# fmt: off
master_key = [
    0x7E, 0x88, 0x97, 0x55, 0x0B, 0x06, 0xF1, 0x08, 0xEB, 0xBB, 0x14, 0x1C, 0xD8,
    0x7A, 0xEC, 0x41, 0x34, 0xB2, 0xA3, 0x46, 0xEF, 0x6B, 0xFE, 0xE1, 0xCF, 0x53,
    0xA5, 0x05, 0x12, 0xD2, 0x8E, 0x52, 0x4A, 0x80, 0xE9, 0x81, 0xB0, 0xF0, 0xB4,
    0x9C, 0xFF, 0x0F, 0x15, 0x13, 0xDA, 0x73, 0x4E, 0x77, 0xBE, 0xD7, 0x30, 0xE5,
    0xF6, 0x5A, 0x11, 0x37, 0x67, 0xBC, 0x83, 0x6F, 0x27, 0x76, 0xD0, 0xCD, 0x69,
    0x0D, 0x2E, 0x51, 0x42, 0x90, 0xB8, 0xB6, 0x4C, 0xAD, 0xCE, 0x5B, 0x1A, 0x1F,
    0xF5, 0xAF, 0x01, 0xF8, 0x5E, 0x3A, 0x6E, 0x68, 0x8B, 0xE8, 0x9F, 0xC9, 0xD9,
    0x26, 0x92, 0x29, 0xC8, 0x33, 0x98, 0x32, 0x54, 0xD4, 0x44, 0x25, 0x66, 0xAC,
    0x5F, 0x99, 0x21, 0xE4, 0x8F, 0x1D, 0xC2, 0xD5, 0xA4, 0x62, 0xF9, 0x02, 0x61,
    0xDE, 0x59, 0xE7, 0x07, 0x9A, 0xFA, 0x2F, 0x95, 0x3F, 0x86, 0xD3, 0x78, 0xA7,
    0x75, 0xED, 0xD6, 0x2D, 0x64, 0x87, 0xBD, 0xC7, 0xC1, 0xAA, 0xF2, 0x8C, 0x17,
    0xCB, 0x31, 0x8A, 0xC3, 0xCC, 0x04, 0xEE, 0x6A, 0xAB, 0x5C, 0x22, 0x70, 0xCA,
    0x9E, 0x71, 0x6D, 0x85, 0x45, 0x5D, 0xB9, 0xA9, 0xA6, 0x10, 0x47, 0xFB, 0x82,
    0x7D, 0x84, 0x7B, 0xC6, 0xE2, 0x38, 0xFC, 0x2B, 0x0E, 0x20, 0x9D, 0xC5, 0xF3,
    0x39, 0xA8, 0xA0, 0x65, 0x58, 0x43, 0x7C, 0xE3, 0x36, 0x18, 0x72, 0x49, 0x79,
    0xAE, 0xD1, 0x74, 0x40, 0xC4, 0x91, 0x4F, 0x24, 0x63, 0xBF, 0xBA, 0x23, 0x96,
    0x50, 0xB3, 0x57, 0xDF, 0x1E, 0x03, 0x48, 0x7F, 0x35, 0x4D, 0x3E, 0xE6, 0xA1,
    0xDD, 0x09, 0x3C, 0x3D, 0x3B, 0x56, 0x8D, 0x93, 0x2A, 0x9B, 0x4B, 0x0C, 0x28,
    0xB1, 0xE0, 0x60, 0x89, 0x19, 0xDB, 0x2C, 0xF7, 0x6C, 0xB5, 0x1B, 0x94, 0xC0,
    0xDC, 0xEA, 0xB7, 0x0A, 0xF4, 0x16, 0xFD, 0xA2, 0x00,
]
# fmt: on

# fmt: off
scramble_key = [
    0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x08,
    0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x40, 0x00,
    0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x1B, 0x00, 0x00, 0x00, 0x36, 0x00, 0x00,
    0x00,
]
# fmt: on

game_path = Path("G:/Games/Kingdom Hearts HD 1.5+2.5 ReMIX/Image")
out_path = game_path.joinpath("out")


# https://github.com/Xeeynamo/OpenKh/pull/474
def generate_key(seed: list, pass_count: int) -> list:
    final_key = [None] * 0xB0
    for i in range(len(seed)):
        final_key[i] = i if seed[i] == 0 else seed[i]

    for i in range(pass_count * 4):
        frame = [
            final_key[0x0C + i * 4],
            final_key[0x0D + i * 4],
            final_key[0x0E + i * 4],
            final_key[0x0F + i * 4],
        ]
        if (i % 4) == 0:
            frame = [
                master_key[frame[1]] ^ scramble_key[i + 0],
                master_key[frame[2]] ^ scramble_key[i + 1],
                master_key[frame[3]] ^ scramble_key[i + 2],
                master_key[frame[0]] ^ scramble_key[i + 3],
            ]

        final_key[0x10 + i * 4] = final_key[0x00 + i * 4] ^ frame[0]
        final_key[0x11 + i * 4] = final_key[0x01 + i * 4] ^ frame[1]
        final_key[0x12 + i * 4] = final_key[0x02 + i * 4] ^ frame[2]
        final_key[0x13 + i * 4] = final_key[0x03 + i * 4] ^ frame[3]

    return final_key


def decrypt_chunk(key: bytes, ptr_data: bytearray, index: int, pass_count: int) -> None:
    for i in reversed(range(pass_count + 1)):
        ptr_data[0x00 + index] ^= key[0x00 + 0x10 * i]
        ptr_data[0x01 + index] ^= key[0x01 + 0x10 * i]
        ptr_data[0x02 + index] ^= key[0x02 + 0x10 * i]
        ptr_data[0x03 + index] ^= key[0x03 + 0x10 * i]
        ptr_data[0x04 + index] ^= key[0x04 + 0x10 * i]
        ptr_data[0x05 + index] ^= key[0x05 + 0x10 * i]
        ptr_data[0x06 + index] ^= key[0x06 + 0x10 * i]
        ptr_data[0x07 + index] ^= key[0x07 + 0x10 * i]
        ptr_data[0x08 + index] ^= key[0x08 + 0x10 * i]
        ptr_data[0x09 + index] ^= key[0x09 + 0x10 * i]
        ptr_data[0x0A + index] ^= key[0x0A + 0x10 * i]
        ptr_data[0x0B + index] ^= key[0x0B + 0x10 * i]
        ptr_data[0x0C + index] ^= key[0x0C + 0x10 * i]
        ptr_data[0x0D + index] ^= key[0x0D + 0x10 * i]
        ptr_data[0x0E + index] ^= key[0x0E + 0x10 * i]
        ptr_data[0x0F + index] ^= key[0x0F + 0x10 * i]


def get_hashes(file_section: str) -> Dict[str, str]:
    config = configparser.ConfigParser()
    config.read("./hashes.ini")
    return dict(config[file_section])


def extract_hed(input_hed: Path):
    input_pkg = input_hed.with_suffix(".pkg")
    infile_hed = open(input_hed, "rb")

    infile_hed.seek(0, os.SEEK_END)
    file_hed_size = infile_hed.tell()
    infile_hed.seek(0)

    hash_dict = get_hashes(input_hed.relative_to(game_path).as_posix())

    entries_hed = []
    for _ in range(file_hed_size // 32):
        hash = "".join([f"{b:02x}" for b in infile_hed.read(16)])
        # print(f"{hash=}")
        offset, padding, compressed_size, decompressed_size = unpack(
            "4I", infile_hed.read(16)
        )
        # print(f"{offset=:08X}")
        if padding != 0:
            print(f"{padding=}")
        # print(f"{compressed_size=}")
        # print(f"{decompressed_size=}")
        try:
            name = hash_dict[hash]
        except KeyError:
            name = hash.upper()
        if name == "":
            name = hash.upper()
        entries_hed.append((name, offset, compressed_size, decompressed_size))

    infile_pkg = open(input_pkg, "rb")
    for i, (
        hed_name,
        hed_offset,
        hed_compressed_size,
        hed_decompressed_size,
    ) in enumerate(entries_hed):
        if infile_pkg.tell() != hed_offset:
            print(f"Error. Last offset: {infile_pkg.tell():08X}")
            print(f"{hed_offset=:08X}")
            exit()
        infile_pkg.seek(hed_offset)
        seed = list(unpack("16B", infile_pkg.read(16)))
        decompressed_size, num_sub_entries, compressed_size, id1 = unpack(
            "4i", bytearray(seed)
        )
        print(f"{hed_name=}")
        # if hed_compressed_size != compressed_size + 16: # Only if num_sub_entries == 0
        # print(f"{hed_compressed_size=}")
        # print(f"{compressed_size=}")
        if hed_decompressed_size != decompressed_size:
            print(f"{hed_decompressed_size=}")
            print(f"{decompressed_size=}")
        print(f"{num_sub_entries=}")
        print(f"{id1=}")

        sub_entries = []
        for _ in range(num_sub_entries):
            asset_name = (
                unpack("32s", infile_pkg.read(32))[0].decode("utf-8").rstrip("\x00")
            )
            (
                asset_unk1,
                asset_unk2,
                asset_decompressed_size,
                asset_compressed_size,
            ) = unpack("4i", infile_pkg.read(16))
            print(f"{asset_name=}")
            print(f"{asset_unk1=}")
            print(f"{asset_unk2=}")
            print(f"{asset_unk1=}")
            # print(f"{asset_compressed_size=}")
            # print(f"{asset_decompressed_size=}")
            sub_entries.append(
                (
                    asset_name,
                    asset_unk1,
                    asset_unk2,
                    asset_decompressed_size,
                    asset_compressed_size,
                )
            )
            # size_sub_entries = sum([se[4] for se in sub_entries])
            # print(f"{size_sub_entries=}")

        pass_count = 10
        key = generate_key(seed, pass_count)
        # print(f"{seed=}")
        # print(f"{key=}")
        file = bytearray(
            infile_pkg.read(
                decompressed_size if compressed_size < 0 else compressed_size
            )
        )
        for i in range(0, min(len(file), 0x100), 0x10):
            decrypt_chunk(key, file, i, pass_count)
        if compressed_size > 0:
            file = zlib.decompress(file)
        file_path = out_path.joinpath(f"{input_hed.stem}/{hed_name}")
        file_path.parent.mkdir(parents=True, exist_ok=True)
        with open(file_path, "wb") as outfile:
            outfile.write(file)

        for (
            asset_name,
            asset_unk1,
            asset_unk2,
            asset_decompressed_size,
            asset_compressed_size,
        ) in sub_entries:
            asset_decompressed_size_padding = (
                asset_decompressed_size
                if asset_decompressed_size % 16 == 0
                else 16 + (asset_decompressed_size // 16) * 16
            )
            # print(f"{asset_decompressed_size_padding=}")
            sub_file = bytearray(
                infile_pkg.read(
                    asset_decompressed_size_padding
                    if asset_compressed_size < 0
                    else asset_compressed_size
                )
            )
            for i in range(0, min(len(sub_file), 0x100), 0x10):
                decrypt_chunk(key, sub_file, i, pass_count)
            if asset_compressed_size > 0:
                sub_file = zlib.decompress(sub_file)
            with open(
                file_path.parent.joinpath(f"{file_path.stem}{asset_name}"), "wb"
            ) as outfile:
                outfile.write(sub_file)

        # print(f"-------------- {infile_pkg.tell():08X}")
        print("--------------")


extract_hed(game_path.joinpath("en/bbs_first.hed"))

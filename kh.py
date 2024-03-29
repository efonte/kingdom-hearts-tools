#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import configparser
import io
import os
import zlib
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from struct import pack, unpack
from typing import Dict, List

import typer
from rich import print
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn

UNCOMPRESSED = -1
UNENCRYPTED_AND_UNCOMPRESSED = -2


@dataclass
class EntryHED:
    md5: str = ""
    offset: int = None
    compressed_size: int = None
    decompressed_size: int = None
    name: str = ""

    def __init__(self) -> None:
        pass


@dataclass
class Asset:
    name: str = ""
    offset: int = None  # original asset's header size + header sizes of all remastered assets + length of the original asset's decompressed data
    original_asset_offset: int = None
    decompressed_size: int = None
    compressed_size: int = None

    def __init__(self) -> None:
        pass

    @property
    def decompressed_size_padding(self):
        return size_with_padding(self.decompressed_size)

    @property
    def is_compressed(self):
        return self.compressed_size >= 0

    @property
    def is_encrypted(self):
        return self.compressed_size != UNENCRYPTED_AND_UNCOMPRESSED


@dataclass
class EntryPKG:
    entry_hed: EntryHED = None
    decompressed_size: int = None
    num_assets: int = None
    compressed_size: int = None
    date: datetime = None
    assets: List[Asset] = None

    def __init__(self, entry_hed: EntryHED) -> None:
        self.entry_hed = entry_hed
        self.assets = []

    @property
    def is_compressed(self):
        return self.compressed_size >= 0

    @property
    def is_encrypted(self):
        return self.compressed_size != -2


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


def size_with_padding(size: int) -> int:
    return size if size % 16 == 0 else 16 + (size // 16) * 16


# https://github.com/Xeeynamo/OpenKh/pull/474
def generate_key(seed: list, pass_count: int = 10) -> list:
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


def decrypt_chunk(
    key: bytes, ptr_data: bytearray, index: int, pass_count: int = 10
) -> None:
    for i in reversed(range(pass_count + 1)):
        for j in range(0xF + 1):
            ptr_data[j + index] ^= key[j + 0x10 * i]


def encrypt_chunk(
    key: bytes, ptr_data: bytearray, index: int, pass_count: int = 10
) -> None:
    decrypt_chunk(key, ptr_data, index, pass_count)


def get_hashes(hed_path: Path) -> Dict[str, str]:
    file_section = hed_path.relative_to(get_image_path(hed_path)).as_posix()
    config = configparser.ConfigParser()
    config.read("./hashes.ini")
    try:
        return dict(config[file_section])
    except KeyError:
        # return all the hashes
        return {
            k: v for section in config.sections() for k, v in config[section].items()
        }


def get_last_offset(infile: io.BufferedReader) -> int:
    """
    Get the last offset of a file.

    Parameters:
        infile (io.BufferedReader): The input file.

    Returns:
        int: The last offset of the file.
    """
    current_offset = infile.tell()
    infile.seek(0, os.SEEK_END)
    offset = infile.tell()
    infile.seek(current_offset)
    return offset


def get_image_path(hed_path: Path) -> Path:
    for parent in hed_path.absolute().parents:
        if parent.name == "Image":
            return parent
    print("Error. Image folder from game installation not found.")
    exit(1)


def extract_hed(hed_path: Path, out_path: Path, extract_files: bool = True):
    pkg_path = hed_path.with_suffix(".pkg")
    infile_hed = open(hed_path, "rb")
    hash_dict = get_hashes(hed_path)
    num_entries = get_last_offset(infile_hed) // 32
    out_path.mkdir(parents=True, exist_ok=True)

    with Progress(
        "{task.description}",
        SpinnerColumn(),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
    ) as progress:
        task_hed = progress.add_task("Reading hed file...", total=num_entries)
        entries_hed: List[EntryHED] = []
        for i in range(num_entries):
            entry_hed = EntryHED()
            entry_hed.md5 = "".join([f"{b:02x}" for b in infile_hed.read(16)])
            try:
                entry_hed.name = hash_dict[entry_hed.md5.lower()]
            except KeyError:
                entry_hed.name = ""
            if entry_hed.name == "":
                entry_hed.name = f"{entry_hed.md5.upper()}.dat"
            (
                entry_hed.offset,
                entry_hed.compressed_size,
                entry_hed.decompressed_size,
            ) = unpack("Qii", infile_hed.read(16))
            # print(f"{entry_hed}")

            entries_hed.append(entry_hed)
            progress.advance(task_hed)

        infile_pkg = open(pkg_path, "rb")
        task_pkg = progress.add_task("Reading pkg file...", total=len(entries_hed))
        task_assets = None
        entries_pkg: List[EntryPKG] = []
        for i, entry_hed in enumerate(entries_hed, start=1):
            entry_pkg = EntryPKG(entry_hed)
            if (  # Fix entry 5587 in Recom.hed
                entry_pkg.entry_hed.compressed_size == 0
                and entry_pkg.entry_hed.decompressed_size == -0x2020203
            ):
                entries_pkg.append(entry_pkg)
                progress.advance(task_pkg)
                continue
            offset = infile_pkg.tell()
            if infile_pkg.tell() != entry_hed.offset:
                # print (f"{i=}")
                print(f"Error. Last pkg offset: {infile_pkg.tell():08X}")
                print(f"{entry_hed.offset=:08X}")
                exit()
            # print(f"{infile_pkg.tell():08X}")
            infile_pkg.seek(entry_hed.offset)  # TODO
            seed = list(unpack("16B", infile_pkg.read(16)))
            # print(f"{seed=}")
            (
                entry_pkg.decompressed_size,
                entry_pkg.num_assets,
                entry_pkg.compressed_size,
                date_raw,
            ) = unpack("iIiI", bytearray(seed))
            entry_pkg.date = datetime.fromtimestamp(date_raw)
            # print(f"{entry_hed.name=}")
            # if entry_hed.compressed_size != entry_pkg.compressed_size + 16: # Only if num_assets == 0
            # print(f"{entry_hed.compressed_size=}")
            # print(f"{entry_pkg.compressed_size=}")
            # if entry_hed.decompressed_size != decompressed_size:
            #     print(f"{entry_hed.decompressed_size=}")
            #     print(f"{entry_pkg.decompressed_size=}")
            # print(f"{entry_pkg.num_assets=}")
            # print(f"{entry_pkg.date=}")

            if entry_pkg.num_assets != 0:
                task_assets_desc = f"Extracting assets from file #{str(i).zfill(len(str(len(entries_hed))))}..."
                if not task_assets:
                    task_assets = progress.add_task(
                        task_assets_desc,
                        total=entry_pkg.num_assets,
                    )
                else:
                    progress.update(
                        task_assets,
                        description=task_assets_desc,
                        total=entry_pkg.num_assets,
                    )
            # print(f"{entry_hed}")
            # print(f"{entry_pkg}")
            for _ in range(entry_pkg.num_assets):
                asset = Asset()
                # print(f"{infile_pkg.tell():08X}")
                asset.name = (
                    unpack("32s", infile_pkg.read(32))[0].decode("utf-8").rstrip("\x00")
                )
                (
                    asset.offset,
                    asset.original_asset_offset,
                    asset.decompressed_size,
                    asset.compressed_size,
                ) = unpack("IIii", infile_pkg.read(16))
                # print(f"{asset=}")
                entry_pkg.assets.append(asset)
                progress.advance(task_assets)

            key = generate_key(seed)
            # print(f"{key=}")
            if entry_pkg.compressed_size < 0:
                if (
                    entry_pkg.compressed_size != UNCOMPRESSED
                    and entry_pkg.compressed_size != UNENCRYPTED_AND_UNCOMPRESSED
                ):
                    print(f"{infile_pkg.tell()=:08X} {entry_pkg.compressed_size=:08X}")
                    print(
                        f"'{entry_pkg.entry_hed.name}' {entry_pkg.compressed_size=:08X} {entry_pkg.decompressed_size=:08X} {entry_pkg.date=}"
                    )
                    # exit()
            elif entry_pkg.compressed_size % 16 != 0:
                print("Error entry_pkg.compressed_size % 16 != 0")
                print(f"{infile_pkg.tell():08X}")
                print(f"{entry_pkg.compressed_size=:08X}")
                print(f"{entry_pkg.decompressed_size=:08X}")
                exit()
            file = bytearray(
                infile_pkg.read(
                    entry_pkg.decompressed_size
                    if entry_pkg.compressed_size < 0
                    else entry_pkg.compressed_size
                )
            )

            if entry_pkg.is_encrypted:
                for i in range(0, min(len(file), 0x100), 0x10):
                    decrypt_chunk(key, file, i)
            # if (
            #     entry_pkg.decompressed_size_padding - entry_pkg.decompressed_size > 0
            # ):  # remove padding
            #     file = file[0 : entry_pkg.decompressed_size]
            if entry_pkg.is_compressed:
                file = zlib.decompress(file)
                if len(file) != entry_pkg.decompressed_size:
                    print("Error len(file) != entry_pkg.decompressed_size")
                    print(f"{entry_pkg.decompressed_size=}")
                    print(f"{entry_pkg.compressed_size=}")
                    exit()

            file_path = out_path.joinpath(f"original/{entry_hed.name}")
            if extract_files:
                file_path.parent.mkdir(parents=True, exist_ok=True)
                with open(file_path, "wb") as outfile:
                    # file = file.rstrip(b"\xCD")
                    # if len(file) % 16 == 0:
                    #     print ("Error removing file pading")
                    outfile.write(file)

            for asset in entry_pkg.assets:
                # print(f"{asset.decompressed_size_padding=}")
                if asset.compressed_size < 0:
                    if (
                        asset.compressed_size != UNCOMPRESSED
                        and asset.compressed_size != UNENCRYPTED_AND_UNCOMPRESSED
                    ):
                        print(f"{infile_pkg.tell():08X}")
                        print(f"{asset.compressed_size=:08X}")
                        # exit()
                elif asset.compressed_size % 16 != 0:
                    print("Error asset.compressed_size % 16 != 0")
                    print(f"{infile_pkg.tell():08X}")
                    print(f"{asset.compressed_size=:08X}")
                    print(f"{asset.decompressed_size=:08X}")
                    exit()
                asset_file = bytearray(
                    infile_pkg.read(
                        asset.decompressed_size_padding
                        if asset.compressed_size < 0
                        else asset.compressed_size
                    )
                )

                # print(f"{asset}")
                if asset.compressed_size < 0:
                    if (
                        asset.compressed_size != UNCOMPRESSED
                        and asset.compressed_size != UNENCRYPTED_AND_UNCOMPRESSED
                    ):
                        print(
                            f"{asset.name=} {asset.offset=:08X} {asset.original_asset_offset=:08X} {asset.decompressed_size=:08X} {asset.compressed_size=:08X}"
                        )
                elif asset.compressed_size % 16 != 0:
                    print("Error asset.compressed_size % 16 != 0")
                    print(f"{infile_pkg.tell():08X}")
                    print(f"{asset.compressed_size=:08X}")
                    print(f"{asset.decompressed_size=:08X}")
                    exit()

                if asset.is_encrypted:
                    for i in range(0, min(len(asset_file), 0x100), 0x10):
                        decrypt_chunk(key, asset_file, i)
                if (
                    asset.decompressed_size_padding - asset.decompressed_size > 0
                ):  # remove padding
                    asset_file = asset_file[0 : asset.decompressed_size]
                if asset.is_compressed:
                    asset_file = zlib.decompress(asset_file)
                    if len(asset_file) != asset.decompressed_size_padding:
                        print(
                            "Error len(asset_file) != asset.decompressed_size_padding"
                        )
                        print(f"{infile_pkg.tell():08X}")
                        print(f"{asset.decompressed_size_padding=}")
                        print(f"{asset.compressed_size=}")
                        print(f"{len(asset_file)=}")
                        exit()

                if extract_files:
                    asset_path = out_path.joinpath(
                        f"remastered/{entry_hed.name}/{asset.name}"
                    )
                    asset_path.parent.mkdir(parents=True, exist_ok=True)
                    # print(f"{file_path=}")
                    # print(f"{asset_path=}")
                    with open(asset_path, "wb") as outfile:
                        outfile.write(asset_file)

                # Check sizes
                hed_compressed_size = (
                    entry_pkg.decompressed_size
                    if entry_pkg.compressed_size < 0
                    # or entry_pkg.compressed_size == 0
                    else entry_pkg.compressed_size
                ) + 0x10  # values
                for asset in entry_pkg.assets:
                    hed_compressed_size += (
                        (
                            asset.decompressed_size_padding
                            if asset.compressed_size < 0
                            # or asset.compressed_size == 0
                            else asset.compressed_size
                        )
                        + 0x20  # name
                        + 0x10  # values
                    )
                hed_decompressed_size = entry_pkg.decompressed_size
                if (
                    entry_pkg.entry_hed.compressed_size != hed_compressed_size
                    or entry_pkg.entry_hed.decompressed_size != hed_decompressed_size
                ):
                    print(f"{offset=:08X}")
                    print(f"{infile_pkg.tell():08X}")
                    print(f"{hed_compressed_size=}")
                    print(entry_pkg)
                    exit()

            entries_pkg.append(entry_pkg)
            progress.advance(task_pkg)

        task_ini = progress.add_task(
            "Saving file table ini file...", total=len(entries_pkg)
        )
        config = configparser.ConfigParser()
        for i, entry_pkg in enumerate(entries_pkg):
            entry_pkg_dict = {
                "hed_name": entry_pkg.entry_hed.name,
                "pkg_encrypted": f"{entry_pkg.is_encrypted}",
                "pkg_compressed": f"{entry_pkg.is_compressed}",
                "pkg_date": f"{entry_pkg.date:%Y-%m-%d %H:%M:%S}",
                "pkg_num_assets": f"{entry_pkg.num_assets:X}",
            }
            for j, asset in enumerate(entry_pkg.assets, start=1):
                entry_pkg_dict[f"asset{j}_name"] = asset.name
                entry_pkg_dict[f"asset{j}_offset"] = f"{asset.offset:X}"
                entry_pkg_dict[
                    f"asset{j}_original_asset_offset"
                ] = f"{asset.original_asset_offset:X}"
                entry_pkg_dict[f"asset{j}_encrypted"] = f"{asset.is_encrypted}"
                entry_pkg_dict[f"asset{j}_compressed"] = f"{asset.is_compressed}"
            config[entry_pkg.entry_hed.md5] = entry_pkg_dict
            progress.advance(task_ini)
        with open(out_path.joinpath("@FILETABLE.ini"), "w") as outfile:
            config.write(outfile)


def repack_hed(dir_path: Path, hed_path: Path):
    dir_path = dir_path.absolute()
    config = configparser.ConfigParser()
    config.read(dir_path.joinpath("@FILETABLE.ini"))

    entries_pkg: List[EntryPKG] = []
    for i, md5 in enumerate(config.sections()):
        entry_hed = EntryHED()
        entry_hed.md5 = md5
        # entry_hed.offset = -1
        entry_hed.name = config[md5]["hed_name"]

        entry_pkg = EntryPKG(entry_hed)
        pkg_is_encrypted = config[md5].getboolean("pkg_encrypted")
        pkg_is_compressed = config[md5].getboolean("pkg_compressed")
        if not pkg_is_compressed:
            entry_pkg.compressed_size = (
                UNCOMPRESSED if pkg_is_encrypted else UNENCRYPTED_AND_UNCOMPRESSED
            )
        else:
            entry_pkg.compressed_size = 999_999_999  # calculate from file
        entry_pkg.date = datetime.strptime(config[md5]["pkg_date"], "%Y-%m-%d %H:%M:%S")
        entry_pkg.num_assets = int(config[md5]["pkg_num_assets"], 16)

        for j in range(entry_pkg.num_assets):
            asset = Asset()
            asset.name = config[md5][f"asset{j+1}_name"]
            asset.offset = int(config[md5][f"asset{j+1}_offset"], 16)
            asset.original_asset_offset = int(
                config[md5][f"asset{j+1}_original_asset_offset"], 16
            )
            asset_is_encrypted = config[md5].getboolean(f"asset{j+1}_encrypted")
            asset_is_compressed = config[md5].getboolean(f"asset{j+1}_compressed")
            if not asset_is_compressed:
                asset.compressed_size = (
                    UNCOMPRESSED if asset_is_encrypted else UNENCRYPTED_AND_UNCOMPRESSED
                )
            else:
                asset.compressed_size = 999_999_999  # calculate from file

            entry_pkg.assets.append(asset)
        # print(f"{entry_pkg}")
        entries_pkg.append(entry_pkg)

    outfile_pkg = open(hed_path, "wb")
    outfile_hed = open(hed_path.with_suffix(".hed"), "wb")
    for i, entry_pkg in enumerate(entries_pkg):
        with open(
            dir_path.joinpath(f"original/{entry_pkg.entry_hed.name}"),
            "rb",
        ) as infile:
            file = infile.read()

        offset = outfile_pkg.tell()

        entry_pkg.decompressed_size = len(file)
        if entry_pkg.is_compressed:
            file = zlib.compress(file)
        file += b"\xCD" * (size_with_padding(len(file)) - len(file))  # padding
        file = bytearray(file)
        if entry_pkg.compressed_size == 999_999_999:
            entry_pkg.compressed_size = len(file)

        seed = list(
            pack(
                "iIiI",
                entry_pkg.decompressed_size,
                entry_pkg.num_assets,
                entry_pkg.compressed_size,
                int(entry_pkg.date.timestamp()),
            )
        )
        # print(f"{seed=}")
        key = generate_key(seed)

        if entry_pkg.is_encrypted:
            for j in range(0, min(len(file), 0x100), 0x10):
                encrypt_chunk(key, file, j)

        outfile_pkg.write(bytearray(seed))

        assets_files = []

        for asset in entry_pkg.assets:
            outfile_pkg.write(pack("32s", asset.name.encode("utf-8")))

            with open(
                dir_path.joinpath(
                    f"remastered/{Path(entry_pkg.entry_hed.name)}/{asset.name}"
                ),
                "rb",
            ) as infile:
                asset_file = infile.read()

            asset.decompressed_size = len(asset_file)
            if asset.is_compressed:
                asset_file = zlib.compress(asset_file)
            asset_file += b"\xCD" * (
                size_with_padding(len(asset_file)) - len(asset_file)
            )  # padding
            asset_file = bytearray(asset_file)
            if asset.compressed_size == 999_999_999:
                asset.compressed_size = len(asset_file)

            if asset.is_encrypted:
                for j in range(0, min(len(asset_file), 0x100), 0x10):
                    encrypt_chunk(key, asset_file, j)

            assets_files.append(asset_file)

            outfile_pkg.write(
                pack(
                    "IIii",
                    asset.offset,
                    asset.original_asset_offset,
                    asset.decompressed_size,
                    asset.compressed_size,
                )
            )

        outfile_pkg.write(file)

        for asset_file in assets_files:
            outfile_pkg.write(asset_file)

        outfile_hed.write(bytes.fromhex(entry_pkg.entry_hed.md5))

        hed_compressed_size = (
            entry_pkg.decompressed_size
            if entry_pkg.compressed_size < 0
            else entry_pkg.compressed_size
        ) + 0x10  # values

        for asset in entry_pkg.assets:
            hed_compressed_size += (
                (
                    asset.decompressed_size_padding
                    if asset.compressed_size < 0
                    else asset.compressed_size
                )
                + 0x20  # names
                + 0x10  # values
            )
        hed_decompressed_size = entry_pkg.decompressed_size
        # if (
        #     entry_pkg.entry_hed.compressed_size != hed_compressed_size
        #     or entry_pkg.entry_hed.decompressed_size != hed_decompressed_size
        #     # or i == 293
        # ):
        #     print(f"{entry_pkg.entry_hed.md5=}")
        #     print(f"{offset=:08X}")
        #     print(
        #         f"{i=:04} {entry_pkg.entry_hed.compressed_size=:08X} {entry_pkg.entry_hed.decompressed_size=:08X}"
        #     )
        #     print(f"{i=:04} {hed_compressed_size=:08X} {hed_decompressed_size=:08X}")
        #     print(f"{i=:04} {entry_pkg.compressed_size=:08X} {entry_pkg.decompressed_size=:08X}")
        #     for asset in entry_pkg.assets:
        #         print(
        #             f"{i=:04} {asset.compressed_size=:08X} {asset.decompressed_size=:08X}"
        #         )
        #     # exit()
        outfile_hed.write(
            pack(
                "Qii",
                offset,
                hed_compressed_size,  # I think it is not read by the game
                hed_decompressed_size,  # I think it is not read by the game
            )
        )


app = typer.Typer()


@app.command()
def extract(
    input: Path = typer.Argument(..., help="hed file path"),
    output: Path = typer.Option(None, "--output", "-o", help="folder path"),
    extract: bool = typer.Option(
        True,
        "--extract/--no-extract",
        "-e/-no-e",
        help="Extract files",
    ),
    # verbose: bool = typer.Option(
    #     False,
    #     "--verbose",
    #     "-v",
    #     help="Verbose mode",
    # ),
):
    if not input.is_file():
        print(f'Error. The file "{input}" does not exist.')
        raise typer.Abort()

    if not output:
        output = input.with_suffix("")

    extract_hed(input, output, extract)


@app.command()
def repack(
    input: Path = typer.Argument(..., help="folder path"),
    output: Path = typer.Option(None, "--output", "-o", help="hed file path"),
    # verbose: bool = typer.Option(
    #     False,
    #     "--verbose",
    #     "-v",
    #     help="Verbose mode",
    # ),
):
    if not input.is_dir():
        print(f'Error. The folder "{input}" does not exist.')
        raise typer.Abort()

    if not output:
        # output = input.with_suffix(".pkg")
        output = input.with_name(f"{input.stem}_generated.pkg")

    # if output.is_file():
    #     print(f'Error. The pkg "{output}" already exist.')
    #     raise typer.Abort()

    repack_hed(input, output)


# @app.command()
# def decrypt(
#     input: Path = typer.Argument(..., help="file path"),
# ):
#     if not input.is_file():
#         print(f'Error. The file "{input}" does not exist.')
#         raise typer.Abort()

#     infile = open(input, "rb")
#     seed = list(infile.read(16))  # TODO: find the seed for the mp4 files
#     key = generate_key(seed)
#     infile.seek(0)
#     file = bytearray(infile.read())

#     for i in range(0, min(len(file), 0x100), 0x10):
#         decrypt_chunk(key, file, i)

#     with open(input.with_stem(f"{input.stem}_dec"), "wb") as outfile:
#         outfile.write(file)


if __name__ == "__main__":
    app()

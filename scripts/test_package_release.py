"""Regression coverage for release header checks and atomic package publication."""

from __future__ import annotations

import io
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

import package_release as release


def _macho(machine: int, version: int) -> bytes:
    load = struct.pack("<IIIIII", 0x32, 24, 1, version, version, 0)
    return (
        struct.pack("<IIIIIIII", 0xFEEDFACF, machine, 0, 2, 1, len(load), 0, 0)
        + load
    )


def _pe(machine: int, subsystem: int) -> bytes:
    header = bytearray(64 + 24 + 72)
    header[:2] = b"MZ"
    struct.pack_into("<I", header, 60, 64)
    header[64:68] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", header, 68, machine, 1, 0, 0, 0, 72, 2)
    struct.pack_into("<H", header, 88, 0x20B)
    struct.pack_into("<I", header, 104, 1)
    struct.pack_into("<H", header, 156, subsystem)
    return bytes(header)


def _elf(machine: int, loader: bytes) -> bytes:
    header = bytearray(176)
    header[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHIQQ", header, 16, 3, machine, 1, 0x1000, 64)
    struct.pack_into("<HHH", header, 52, 64, 56, 2)
    struct.pack_into("<IIQQQQQQ", header, 64, 1, 5, 0, 0x1000, 0x1000, 176, 176, 4096)
    struct.pack_into(
        "<IIQQQQQQ", header, 120, 3, 4, 176, 0, 0, len(loader), len(loader), 1
    )
    return bytes(header) + loader


class PackageReleaseTest(unittest.TestCase):
    def test_macos_rejects_wrong_cpu_or_newer_deployment_target(self) -> None:
        machine = release.TARGETS["aarch64-apple-darwin"].machine
        release._validate_macho(io.BytesIO(_macho(machine, 13 << 16)), machine)
        with self.assertRaisesRegex(release.PackageError, "architecture"):
            release._validate_macho(io.BytesIO(_macho(0x01000007, 13 << 16)), machine)
        with self.assertRaisesRegex(release.PackageError, "newer than"):
            release._validate_macho(io.BytesIO(_macho(machine, 14 << 16)), machine)

    def test_windows_rejects_console_and_other_architectures(self) -> None:
        machine = release.TARGETS["x86_64-pc-windows-msvc"].machine
        release._validate_pe(io.BytesIO(_pe(machine, subsystem=2)), machine)
        with self.assertRaisesRegex(release.PackageError, "GUI"):
            release._validate_pe(io.BytesIO(_pe(machine, subsystem=3)), machine)
        with self.assertRaisesRegex(release.PackageError, "x64"):
            release._validate_pe(io.BytesIO(_pe(0xAA64, subsystem=2)), machine)

    def test_linux_rejects_wrong_architecture_or_gnu_loader(self) -> None:
        target = release.TARGETS["aarch64-unknown-linux-gnu"]
        loader = b"/lib/ld-linux-aarch64.so.1\0"
        release._validate_elf(io.BytesIO(_elf(target.machine, loader)), target)
        with self.assertRaisesRegex(release.PackageError, "architecture"):
            release._validate_elf(io.BytesIO(_elf(62, loader)), target)
        with self.assertRaisesRegex(release.PackageError, "GNU target"):
            release._validate_elf(
                io.BytesIO(_elf(target.machine, b"/lib/ld-musl-aarch64.so.1\0")), target
            )

    def test_zip_is_reproducible_and_preserves_executable_mode(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            binary = folder / "app"
            binary.write_bytes(b"synthetic test executable")
            member = release.Member("UninstallAny", binary, release.PERM_EXECUTABLE)
            first = folder / "first.zip"
            second = folder / "second.zip"
            release._write_zip(first, [member])
            release._write_zip(second, [member])
            self.assertEqual(first.read_bytes(), second.read_bytes())
            first_digest = release._verify_archive(first, [member], is_tar=False)
            self.assertEqual(
                first_digest, release._verify_archive(second, [member], is_tar=False)
            )
            with zipfile.ZipFile(first) as package:
                self.assertEqual(
                    package.getinfo(member.name).date_time, (1980, 1, 1, 0, 0, 0)
                )

    def test_size_failure_leaves_no_published_package(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            binary = folder / "bin"
            output = folder / "output"
            platform = release.TARGETS["aarch64-unknown-linux-gnu"]
            binary.write_bytes(_elf(platform.machine, b"/lib/ld-linux-aarch64.so.1\0"))
            with (
                patch.object(release, "MAX_ARCHIVE_BYTES", 1),
                self.assertRaisesRegex(release.PackageError, "Required < 1"),
            ):
                release._publish(binary, platform, "1.2.3", output)
            self.assertEqual(list(output.iterdir()), [])


if __name__ == "__main__":
    unittest.main()

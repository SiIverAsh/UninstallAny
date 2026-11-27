#!/usr/bin/env python3
"""Package a trusted, prebuilt UninstallAny Debian helper into a local .deb."""

from __future__ import annotations

import argparse
import gzip
import io
import os
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import Final

from package_release import (
    MAX_ARCHIVE_BYTES,
    PERM_EXECUTABLE,
    PERM_RESOURCE,
    PROJECT,
    TARGETS,
    PackageError,
    _project_version,
    _validate_elf,
)

HELPER_NAME: Final = "uninstallany-dpkg-helper"
POLICY_NAME: Final = "io.github.siiverash.uninstallany.dpkg.policy"
POLICY_SOURCE: Final = PROJECT / "packaging" / "debian-dpkg-helper" / POLICY_NAME
HELPER_PATH: Final = PurePosixPath("usr/libexec") / HELPER_NAME
POLICY_PATH: Final = PurePosixPath("usr/share/polkit-1/actions") / POLICY_NAME
ARCHITECTURES: Final = {
    "amd64": TARGETS["x86_64-unknown-linux-gnu"],
    "arm64": TARGETS["aarch64-unknown-linux-gnu"],
}
AR_MAGIC: Final = b"!<arch>\n"
AR_FILE_MODE: Final = 0o100644


def _read_helper(binary: Path, arch: str) -> bytes:
    if binary.name != HELPER_NAME or not binary.is_file() or binary.is_symlink():
        raise PackageError(f"Choose a trusted, regular {HELPER_NAME} binary: {binary}")
    with binary.open("rb") as source:
        payload = source.read(MAX_ARCHIVE_BYTES)
    if len(payload) >= MAX_ARCHIVE_BYTES:
        raise PackageError(
            f"The helper executable must be smaller than {MAX_ARCHIVE_BYTES:,} bytes."
        )
    _validate_elf(io.BytesIO(payload), ARCHITECTURES[arch])
    return payload


def _control(version: str, arch: str, installed_size: int) -> bytes:
    return (
        f"Package: {HELPER_NAME}\n"
        f"Version: {version}\n"
        f"Architecture: {arch}\n"
        "Section: admin\n"
        "Priority: optional\n"
        "Maintainer: UninstallAny contributors <uninstallany@localhost>\n"
        f"Installed-Size: {installed_size}\n"
        "Depends: dpkg (>= 1.20.1), pkexec | policykit-1, libc6 (>= 2.31), libgcc-s1\n"
        "Homepage: https://github.com/SiIverAsh/UninstallAny\n"
        "Description: UninstallAny helper for removing Debian packages\n"
        " Requests administrator authentication for an explicitly approved\n"
        " package removal through the system's package manager.\n"
    ).encode("ascii")


def _tar_gz(files: dict[PurePosixPath, tuple[bytes, int]]) -> bytes:
    stream = io.BytesIO()
    with (
        gzip.GzipFile(filename="", mode="wb", fileobj=stream, mtime=0) as compressed,
        tarfile.open(
            fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT
        ) as archive,
    ):
        directories = {parent for path in files for parent in path.parents}
        for directory in sorted(directories):
            name = "." if directory == PurePosixPath(".") else f"./{directory}"
            # TarInfo defaults to numeric root ownership and epoch timestamps.
            entry = tarfile.TarInfo(name)
            entry.type = tarfile.DIRTYPE
            entry.mode = PERM_EXECUTABLE
            archive.addfile(entry)
        for path, (contents, mode) in sorted(files.items()):
            entry = tarfile.TarInfo(f"./{path}")
            entry.mode = mode
            entry.size = len(contents)
            archive.addfile(entry, io.BytesIO(contents))
    return stream.getvalue()


def _ar_member(name: str, contents: bytes) -> bytes:
    # Debian binary packages use short ar names and one newline of odd-byte padding.
    header = (
        f"{name + '/':<16}{0:<12}{0:<6}{0:<6}{AR_FILE_MODE:<8o}{len(contents):<10}`\n"
    ).encode("ascii")
    padding = b"\n" if len(contents) % 2 else b""
    return header + contents + padding


def _package(binary: Path, arch: str, output: Path) -> Path:
    version = _project_version()
    helper = _read_helper(binary, arch)
    policy = POLICY_SOURCE.read_bytes()
    installed_size = (len(helper) + len(policy) + 1023) // 1024
    metadata = _control(version, arch, installed_size)
    control = _tar_gz({PurePosixPath("control"): (metadata, PERM_RESOURCE)})
    payload = _tar_gz(
        {HELPER_PATH: (helper, PERM_EXECUTABLE), POLICY_PATH: (policy, PERM_RESOURCE)}
    )
    package = AR_MAGIC + b"".join(
        (
            _ar_member("debian-binary", b"2.0\n"),
            _ar_member("control.tar.gz", control),
            _ar_member("data.tar.gz", payload),
        )
    )
    if len(package) >= MAX_ARCHIVE_BYTES:
        raise PackageError(
            f"The Debian package must be smaller than {MAX_ARCHIVE_BYTES:,} bytes."
        )

    output.mkdir(parents=True, exist_ok=True)
    destination = output / f"{HELPER_NAME}_{version}_{arch}.deb"
    # A hard link publishes the completed file and fails if the name is occupied.
    with tempfile.TemporaryDirectory(
        prefix=".uninstallany-dpkg-", dir=output
    ) as temporary:
        staged = Path(temporary) / destination.name
        staged.write_bytes(package)
        staged.chmod(PERM_RESOURCE)
        try:
            os.link(staged, destination)
        except FileExistsError as error:
            raise PackageError(f"Output already exists: {destination}") from error
    return destination


def main() -> int:
    """Validate the package inputs and write the local .deb without installing it."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--binary", required=True, type=Path, help="trusted prebuilt helper"
    )
    parser.add_argument("--arch", required=True, choices=ARCHITECTURES)
    parser.add_argument("--output-dir", type=Path, default=PROJECT / "target" / "dist")
    args = parser.parse_args()
    try:
        destination = _package(args.binary, args.arch, args.output_dir)
    except (OSError, PackageError) as error:
        parser.exit(1, f"{error}\n")
    print(destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

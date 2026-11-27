#!/usr/bin/env python3
"""Build and verify a desktop archive with optional macOS distribution signing."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import platform
import plistlib
import re
import shutil
import stat
import struct
import subprocess
import tarfile
import tempfile
import tomllib
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Final

PROJECT: Final = Path(__file__).resolve().parents[1]
APP_NAME: Final = "UninstallAny"
PACKAGE: Final = "uninstallany-gui"
CLI_PACKAGE: Final = "uninstallany-cli"
CLI_BINARY: Final = "uninstallany"
BUNDLE_ID: Final = "io.github.siiverash.uninstallany"
MACOS_MINIMUM: Final = "13.0"
MACOS_BACKEND: Final = PROJECT / "crates" / "uninstallany-macos"
TAURI_MANIFEST: Final = PROJECT / "apps" / "macos-host" / "Cargo.toml"
TAURI_DESKTOP: Final = "uninstallany-desktop"
MACOS_HELPER_FEATURE: Final = "macos-privileged-helper"
MACOS_HELPER_NAME: Final = "UninstallAnyPrivilegedHelper"
MACOS_HELPER_ID: Final = f"{BUNDLE_ID}.privileged-helper"
MACOS_HELPER_PLIST: Final = f"{MACOS_HELPER_ID}.plist"
MACOS_HELPER_PATH: Final = Path("Contents/MacOS") / MACOS_HELPER_NAME
MACOS_JOB_PATH: Final = Path("Contents/Library/LaunchDaemons") / MACOS_HELPER_PLIST
WINDOWS_LOADER_NAME: Final = "WebView2Loader.dll"
WINDOWS_DYNAMIC_TARGET: Final = "x86_64-pc-windows-gnullvm"
WINDOWS_PORTABLE_README: Final = """UninstallAny Windows x64 便携预览

系统需已安装 Microsoft Edge WebView2 Runtime。
解压全部文件，再以普通用户打开 UninstallAny.exe。
本包沿用输入文件的签名状态。未签名的桌面程序适用于本地预览。
机器级 MSI 提权功能需要单独部署的签名助手和受保护的安装目录。

UninstallAny Windows x64 portable preview

Microsoft Edge WebView2 Runtime must already be installed.
Extract all files and start UninstallAny.exe as a standard user.
The archive preserves the input files' signature state. An unsigned desktop
executable is intended for local preview.
Machine-wide MSI elevation requires a separately deployed, signed helper
and a protected installation directory.
"""
CODESIGN: Final = "/usr/bin/codesign"
TEAM_LINE: Final = re.compile(r"^TeamIdentifier=([A-Z0-9]{10})$", re.MULTILINE)
SIGNATURE_FLAGS: Final = re.compile(r"\bflags=0x([0-9a-fA-F]+)\(")
HELPER_PROBE: Final = re.compile(
    rb'^#define UA_PROBE_REPLY @"([A-Za-z0-9.-]+)"$', re.MULTILINE
)
MAX_ARCHIVE_BYTES: Final = 15_000_000
ZIP_TIMESTAMP: Final = (1980, 1, 1, 0, 0, 0)
PERM_EXECUTABLE: Final = 0o755
PERM_RESOURCE: Final = 0o644
VERSION_PATTERN: Final = re.compile(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)*")

# Executable format constants from the PE, Mach-O and ELF platform specifications.
IMAGE_GUI: Final = 2
IMAGE_EXECUTABLE: Final = 0x0002
IMAGE_DLL: Final = 0x2000
PE32_PLUS: Final = 0x20B
MACH_EXECUTABLE: Final = 2
MACH_LOAD_VERSION_MACOS: Final = 0x24
MACH_LOAD_BUILD_VERSION: Final = 0x32
MACH_PLATFORM_MACOS: Final = 1
MACH_SIGNATURE_RUNTIME: Final = 0x10000
MAX_MACH_COMMAND_BYTES: Final = 1_048_576
ELF_EXECUTABLE: Final = 2
ELF_POSITION_INDEPENDENT: Final = 3
ELF_SEGMENT_LOAD: Final = 1
ELF_SEGMENT_INTERPRETER: Final = 3
ELF_PERMISSION_EXECUTE: Final = 1
MAX_PROGRAM_HEADERS: Final = 256


class PackageError(Exception):
    """Report a validation or delivery failure without publishing an archive."""


@dataclass(frozen=True)
class Target:
    """Expected executable format, architecture and public filename label."""

    system: str
    arch: str
    machine: int
    loader: bytes | None = None


TARGETS: Final = {
    "x86_64-pc-windows-msvc": Target("windows", "x64", 0x8664),
    WINDOWS_DYNAMIC_TARGET: Target("windows", "x64", 0x8664),
    "aarch64-apple-darwin": Target("macos", "arm64", 0x0100000C),
    "x86_64-apple-darwin": Target("macos", "x64", 0x01000007),
    "aarch64-unknown-linux-gnu": Target(
        "linux", "arm64", 183, b"/lib/ld-linux-aarch64.so.1\0"
    ),
    "x86_64-unknown-linux-gnu": Target(
        "linux", "x64", 62, b"/lib64/ld-linux-x86-64.so.2\0"
    ),
}


@dataclass(frozen=True)
class Member:
    """One exact package member with reproducible archive permissions."""

    name: str
    path: Path
    mode: int = PERM_RESOURCE


@dataclass(frozen=True)
class MacSigning:
    """Explicit Developer ID settings and the matching embedded helper."""

    identity: str
    helper: Path
    notary_profile: str | None


def _native_target() -> str:
    machine = platform.machine().lower()
    machine = {"arm64": "aarch64", "amd64": "x86_64"}.get(machine, machine)
    suffix = {
        "Darwin": "apple-darwin",
        "Windows": "pc-windows-msvc",
        "Linux": "unknown-linux-gnu",
    }.get(platform.system())
    triple = f"{machine}-{suffix}"
    if triple not in TARGETS:
        raise PackageError("This native system is unsupported. Specify --target.")
    return triple


def _project_version() -> str:
    with (PROJECT / "Cargo.toml").open("rb") as manifest:
        version = tomllib.load(manifest)["workspace"]["package"]["version"]
    if not VERSION_PATTERN.fullmatch(version):
        raise PackageError(f"Invalid release version in Cargo.toml: {version!r}")
    return version


def _cargo_build(
    triple: str, target: Target, *, macos_helper: bool = False, cli: bool = False
) -> tuple[list[str], dict[str, str], Path]:
    env = os.environ.copy()
    build_dir = PROJECT / "target"
    if target.system == "macos" and not cli:
        # Concurrent preview and signed builds must not replace each other's executable.
        build_dir /= "macos-host-with-helper" if macos_helper else "macos-host"
    elif target.system == "windows":
        build_dir /= "macos-host"
    args = [
        "cargo",
        "build",
        "--release",
        "--offline",
        "--locked",
        "--target",
        triple,
        "--target-dir",
        str(build_dir),
    ]
    if target.system == "macos":
        env["MACOSX_DEPLOYMENT_TARGET"] = MACOS_MINIMUM
    if cli:
        args.extend(("--package", CLI_PACKAGE, "--bin", CLI_BINARY))
    elif target.system in {"macos", "windows"}:
        # Use the checked-in asset location and content security policy.
        env.pop("TAURI_CONFIG", None)
        args.extend(("--manifest-path", str(TAURI_MANIFEST), "--bin", TAURI_DESKTOP))
        if macos_helper:
            args.extend(("--features", MACOS_HELPER_FEATURE))
    else:
        args.extend(("--package", PACKAGE))
    if target.system == "windows":
        # Ship no VC redistributable. Keep the GUI entry point and link the CRT.
        rustflags = f'target.{triple}.rustflags=["-Ctarget-feature=+crt-static"]'
        args.extend(("--config", rustflags))
    return args, env, build_dir / triple / "release"


def _build(triple: str, target: Target, *, cli: bool = False) -> tuple[Path, Path | None]:
    args, env, release = _cargo_build(triple, target, cli=cli)
    if triple == WINDOWS_DYNAMIC_TARGET:
        messages = _build_messages(args, env)
        return release / f"{TAURI_DESKTOP}.exe", _find_windows_loader(
            messages, release, target.arch
        )
    subprocess.run(args, cwd=PROJECT, env=env, check=True)
    name = CLI_BINARY if cli else {
        "macos": TAURI_DESKTOP,
        "windows": f"{TAURI_DESKTOP}.exe",
        "linux": PACKAGE,
    }[target.system]
    return release / name, None


def _signed_macos_build(triple: str, target: Target) -> tuple[Path, Path]:
    args, env, release = _cargo_build(triple, target, macos_helper=True)
    return _find_macos_artifacts(_build_messages(args, env), release)


def _build_messages(args: list[str], env: dict[str, str]) -> str:
    return subprocess.run(
        [*args, "--message-format=json-render-diagnostics"],
        cwd=PROJECT,
        env=env,
        check=True,
        stdout=subprocess.PIPE,
        encoding="utf-8",
    ).stdout


def _cargo_events(messages: str) -> Iterator[dict[str, object]]:
    for line in messages.splitlines():
        if not line.startswith("{"):
            continue
        try:
            message: object = json.loads(line)
        except json.JSONDecodeError as error:
            raise PackageError("Cargo returned an invalid artifact event.") from error
        if isinstance(message, dict):
            yield message


def _find_windows_loader(messages: str, release: Path, arch: str) -> Path:
    events = tuple(_cargo_events(messages))
    package_ids: set[str] = set()
    for event in events:
        target = event.get("target")
        package_id = event.get("package_id")
        if (
            event.get("reason") == "compiler-artifact"
            and isinstance(target, dict)
            and target.get("name") == "webview2_com_sys"
            and target.get("kind") == ["lib"]
            and isinstance(package_id, str)
        ):
            package_ids.add(package_id)
    loaders: set[Path] = set()
    build_root = (release / "build").resolve()
    for event in events:
        package_id = event.get("package_id")
        out_dir = event.get("out_dir")
        if (
            event.get("reason") == "build-script-executed"
            and isinstance(package_id, str)
            and package_id in package_ids
            and isinstance(out_dir, str)
        ):
            loader = (Path(out_dir) / arch / WINDOWS_LOADER_NAME).resolve()
            if loader.is_relative_to(build_root):
                loaders.add(loader)
    if len(loaders) != 1:
        raise PackageError("Cargo did not identify a unique WebView2 loader for the Windows target.")
    return next(iter(loaders))


def _find_macos_artifacts(messages: str, release: Path) -> tuple[Path, Path]:
    gui_manifest = str(TAURI_MANIFEST)
    helper_manifest = str(MACOS_BACKEND / "Cargo.toml")
    executables: set[Path] = set()
    backend_ids: set[str] = set()
    out_dirs: list[tuple[str, Path]] = []
    for message in _cargo_events(messages):
        reason: object = message.get("reason")
        package_id: object = message.get("package_id")
        if reason == "build-script-executed" and isinstance(package_id, str):
            out_dir: object = message.get("out_dir")
            if isinstance(out_dir, str):
                out_dirs.append((package_id, Path(out_dir)))
        if reason != "compiler-artifact":
            continue
        manifest: object = message.get("manifest_path")
        features: object = message.get("features")
        target: object = message.get("target")
        if not isinstance(features, list) or not isinstance(target, dict):
            continue
        if manifest == gui_manifest and MACOS_HELPER_FEATURE in features:
            executable: object = message.get("executable")
            if (
                target.get("kind") == ["bin"]
                and target.get("name") == TAURI_DESKTOP
                and isinstance(executable, str)
            ):
                executables.add(Path(executable).resolve())
        if (
            manifest == helper_manifest
            and target.get("kind") == ["lib"]
            and "privileged-inspection" in features
            and isinstance(package_id, str)
        ):
            backend_ids.add(package_id)
    expected_gui = (release / TAURI_DESKTOP).resolve()
    if executables != {expected_gui}:
        raise PackageError("Cargo did not report a GUI binary with helper support.")
    build_root = (release / "build").resolve()
    helpers: set[Path] = set()
    for package_id, directory in out_dirs:
        if package_id in backend_ids:
            folder = directory.resolve()
            if folder.is_relative_to(build_root):
                helpers.add(folder / MACOS_HELPER_NAME)
    if len(helpers) != 1:
        raise PackageError("Cargo did not identify a unique helper for the macOS target.")
    return expected_gui, next(iter(helpers))


def _read_at(source: BinaryIO, offset: int, size: int) -> bytes:
    source.seek(offset)
    data = source.read(size)
    if len(data) != size:
        raise PackageError("The input executable has a truncated header or segment.")
    return data


def _read_pe_headers(source: BinaryIO, machine: int) -> tuple[bytes, int]:
    base = _read_at(source, 0, 64)
    if base[:2] != b"MZ":
        raise PackageError("Windows packaging requires a PE executable.")
    (offset,) = struct.unpack_from("<I", base, 60)
    header = _read_at(source, offset, 24)
    if header[:4] != b"PE\0\0":
        raise PackageError("The input does not contain a PE image header.")
    actual, sections, _, _, _, optional_size, flags = struct.unpack_from(
        "<HHIIIHH", header, 4
    )
    if (
        actual != machine
        or not sections
        or not flags & IMAGE_EXECUTABLE
        or optional_size < 72
    ):
        raise PackageError("Expected an executable Windows x64 PE image.")
    optional = _read_at(source, offset + len(header), optional_size)
    (kind,) = struct.unpack_from("<H", optional)
    if kind != PE32_PLUS:
        raise PackageError("Expected a PE32+ optional header.")
    return optional, flags


def _validate_pe(source: BinaryIO, machine: int) -> None:
    optional, flags = _read_pe_headers(source, machine)
    (entry,) = struct.unpack_from("<I", optional, 16)
    (subsystem,) = struct.unpack_from("<H", optional, 68)
    if flags & IMAGE_DLL or not entry or subsystem != IMAGE_GUI:
        raise PackageError("Expected a Windows x64 GUI image with an entry point.")


def _validate_windows_dll(source: BinaryIO, machine: int) -> None:
    """Check the PE format, machine type and DLL characteristic."""
    _, flags = _read_pe_headers(source, machine)
    if not flags & IMAGE_DLL:
        raise PackageError("Expected a Windows DLL image.")


def _validate_macho(source: BinaryIO, machine: int) -> None:
    header = _read_at(source, 0, 32)
    if header[:4] != b"\xcf\xfa\xed\xfe":
        raise PackageError("macOS packaging requires a thin 64-bit Mach-O executable.")
    actual, _, kind, commands, size = struct.unpack_from("<IIIII", header, 4)
    if (
        actual != machine
        or kind != MACH_EXECUTABLE
        or not 0 < size <= MAX_MACH_COMMAND_BYTES
        or not 0 < commands <= size // 8
    ):
        raise PackageError("Mach-O architecture or executable type does not match.")
    load = _read_at(source, len(header), size)
    advertised = tuple(map(int, MACOS_MINIMUM.split(".")))
    _validate_macho_load_commands(load, commands, advertised)


def _validate_macho_load_commands(
    load: bytes, commands: int, advertised: tuple[int, ...]
) -> None:
    offset = 0
    min_version: int | None = None
    for _ in range(commands):
        if offset + 8 > len(load):
            raise PackageError("Mach-O load-command list is truncated.")
        command, size = struct.unpack_from("<II", load, offset)
        if size < 8 or size % 8 or offset + size > len(load):
            raise PackageError("Mach-O contains an invalid load-command size.")
        if command == MACH_LOAD_BUILD_VERSION:
            if size < 24:
                raise PackageError("Mach-O build-version command is truncated.")
            system, min_version = struct.unpack_from("<II", load, offset + 8)
            if system != MACH_PLATFORM_MACOS:
                raise PackageError("Mach-O build-version platform is not macOS.")
        elif command == MACH_LOAD_VERSION_MACOS:
            if size != 16:
                raise PackageError("Invalid legacy macOS deployment command.")
            (min_version,) = struct.unpack_from("<I", load, offset + 8)
        offset += size
    if offset != len(load) or min_version is None:
        raise PackageError("Mach-O does not identify a valid macOS deployment target.")
    version = (min_version >> 16, (min_version >> 8) & 0xFF, min_version & 0xFF)
    if version > (*advertised, 0):
        raise PackageError(f"Mach-O requires macOS newer than {MACOS_MINIMUM}.")


def _validate_elf(source: BinaryIO, target: Target) -> None:
    header = _read_at(source, 0, 64)
    if header[:7] != b"\x7fELF\x02\x01\x01" or header[7] not in (0, 3):
        raise PackageError("Linux packaging requires a little-endian 64-bit ELF image.")
    kind, machine, _, entry, table = struct.unpack_from("<HHIQQ", header, 16)
    _, record_size, count = struct.unpack_from("<HHH", header, 52)
    if (
        machine != target.machine
        or kind not in (ELF_EXECUTABLE, ELF_POSITION_INDEPENDENT)
        or not entry
        or not table
        or record_size != 56
        or not 0 < count <= MAX_PROGRAM_HEADERS
    ):
        raise PackageError("ELF architecture, entry point or program table mismatch.")
    entry_valid = False
    loader: bytes | None = None
    for index in range(count):
        segment = _read_at(source, table + index * record_size, record_size)
        flag, permission, offset, address, _, size = struct.unpack_from(
            "<IIQQQQ", segment
        )
        if flag == ELF_SEGMENT_LOAD and permission & ELF_PERMISSION_EXECUTE:
            entry_valid |= address <= entry < address + size
        if flag == ELF_SEGMENT_INTERPRETER:
            expected = target.loader
            if loader is not None or expected is None or size != len(expected):
                raise PackageError("ELF interpreter does not match the GNU target.")
            loader = _read_at(source, offset, size)
    if not entry_valid or loader != target.loader:
        raise PackageError("ELF requires the target GNU loader and executable entry.")


def _validate_binary(binary: Path, target: Target) -> None:
    if not binary.is_file():
        raise PackageError(f"Release executable not found: {binary}")
    with binary.open("rb") as source:
        match target.system:
            case "windows":
                _validate_pe(source, target.machine)
            case "macos":
                _validate_macho(source, target.machine)
            case "linux":
                _validate_elf(source, target)


def _validate_helper_protocol(binary: Path) -> None:
    protocol = (MACOS_BACKEND / "helper" / "protocol.h").read_bytes()
    marker = HELPER_PROBE.search(protocol)
    if marker is None or marker.group(1) + b"\0" not in binary.read_bytes():
        raise PackageError("The helper does not match this source's XPC protocol.")


def _signature_team(code: Path) -> str:
    details = subprocess.run(
        [CODESIGN, "--display", "--verbose=4", str(code)],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        encoding="utf-8",
    ).stderr
    teams = TEAM_LINE.findall(details)
    flags = SIGNATURE_FLAGS.search(details)
    if (
        len(teams) != 1
        or flags is None
        or not int(flags.group(1), 16) & MACH_SIGNATURE_RUNTIME
        or re.search(r"^Timestamp=\S", details, re.MULTILINE) is None
    ):
        raise PackageError(f"Missing signing team, timestamp or runtime seal: {code.name}")
    return teams[0]


def _verify_developer_bundle(bundle: Path) -> None:
    helper = bundle / MACOS_HELPER_PATH
    team = _signature_team(bundle)
    if _signature_team(helper) != team:
        raise PackageError("The application and privileged helper signing teams differ.")
    for path, identifier in ((helper, MACOS_HELPER_ID), (bundle, BUNDLE_ID)):
        requirement = (
            f'anchor apple generic and identifier "{identifier}" '
            f'and certificate leaf[subject.OU] = "{team}" '
            "and certificate 1[field.1.2.840.113635.100.6.2.6] exists "
            "and certificate leaf[field.1.2.840.113635.100.6.1.13] exists "
            "and !(entitlement[com.apple.security.get-task-allow] exists) "
            "and !(entitlement[com.apple.security.cs.disable-library-validation] "
            "exists) and !(entitlement[com.apple.security.cs."
            "allow-dyld-environment-variables] exists)"
        )
        subprocess.run(
            [CODESIGN, "--verify", "--strict", "-R", f"={requirement}", str(path)],
            check=True,
        )
    subprocess.run(
        [CODESIGN, "--verify", "--deep", "--strict", str(bundle)], check=True
    )


def _sign_privileged_bundle(bundle: Path, target: Target, signing: MacSigning) -> None:
    helper = bundle / MACOS_HELPER_PATH
    shutil.copyfile(signing.helper, helper)
    helper.chmod(PERM_EXECUTABLE)
    _validate_binary(helper, target)
    _validate_helper_protocol(helper)

    job = bundle / MACOS_JOB_PATH
    job.parent.mkdir(parents=True)
    shutil.copyfile(MACOS_BACKEND / "helper" / MACOS_HELPER_PLIST, job)
    sign = [
        CODESIGN,
        "--force",
        "--sign",
        signing.identity,
        "--timestamp",
        "--options",
        "runtime",
    ]
    subprocess.run([*sign, "--identifier", MACOS_HELPER_ID, str(helper)], check=True)
    subprocess.run([*sign, "--identifier", BUNDLE_ID, str(bundle)], check=True)
    _verify_developer_bundle(bundle)


def _notarize_mac_bundle(bundle: Path, profile: str) -> None:
    submission = bundle.parent / "notary-submission.zip"
    subprocess.run(
        ["/usr/bin/ditto", "-c", "-k", "--keepParent", str(bundle), str(submission)],
        check=True,
    )
    result = subprocess.run(
        [
            "/usr/bin/xcrun",
            "notarytool",
            "submit",
            str(submission),
            "--keychain-profile",
            profile,
            "--wait",
            "--output-format",
            "json",
        ],
        check=True,
        stdout=subprocess.PIPE,
        encoding="utf-8",
    )
    try:
        submitted: object = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise PackageError("The notary service did not return a JSON status.") from error
    if not isinstance(submitted, dict) or submitted.get("status") != "Accepted":
        raise PackageError("The Apple notary service did not accept the app.")
    subprocess.run(["/usr/bin/xcrun", "stapler", "staple", str(bundle)], check=True)


def _signed_bundle_members(bundle: Path, stage: Path) -> list[Member]:
    executable_paths = {Path("Contents/MacOS") / APP_NAME, MACOS_HELPER_PATH}
    members: list[Member] = []
    for path in bundle.rglob("*"):
        if path.is_symlink():
            raise PackageError(f"Unexpected symlink in signed app: {path.name}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise PackageError(f"Unexpected entry type in signed app: {path.name}")
        relative = path.relative_to(bundle)
        mode = PERM_EXECUTABLE if relative in executable_paths else PERM_RESOURCE
        members.append(Member(path.relative_to(stage).as_posix(), path, mode))
    return members


def _mac_app(
    binary: Path, stage: Path, version: str, target: Target, signing: MacSigning | None
) -> list[Member]:
    bundle = stage / f"{APP_NAME}.app"
    contents = bundle / "Contents"
    executable = contents / "MacOS" / APP_NAME
    executable.parent.mkdir(parents=True)
    shutil.copyfile(binary, executable)
    executable.chmod(PERM_EXECUTABLE)
    plist = contents / "Info.plist"
    numeric_version = re.split(r"[-+]", version, maxsplit=1)[0]
    info = {
        "CFBundleDisplayName": APP_NAME,
        "CFBundleExecutable": APP_NAME,
        "CFBundleIdentifier": BUNDLE_ID,
        "CFBundleInfoDictionaryVersion": "6.0",
        "CFBundleName": APP_NAME,
        "CFBundlePackageType": "APPL",
        "CFBundleShortVersionString": numeric_version,
        "CFBundleVersion": numeric_version,
        "LSMinimumSystemVersion": MACOS_MINIMUM,
        "NSHighResolutionCapable": True,
    }
    plist.write_bytes(plistlib.dumps(info))
    if signing is not None:
        _sign_privileged_bundle(bundle, target, signing)
        if signing.notary_profile is not None:
            _notarize_mac_bundle(bundle, signing.notary_profile)
        return _signed_bundle_members(bundle, stage)
    subprocess.run(
        ["codesign", "--force", "--sign", "-", "--timestamp=none", str(bundle)],
        check=True,
    )
    subprocess.run(["codesign", "--verify", "--strict", str(bundle)], check=True)
    resources = contents / "_CodeSignature" / "CodeResources"
    return [
        Member(plist.relative_to(stage).as_posix(), plist),
        Member(executable.relative_to(stage).as_posix(), executable, PERM_EXECUTABLE),
        Member(resources.relative_to(stage).as_posix(), resources),
    ]


def _package_members(
    binary: Path,
    stage: Path,
    target: Target,
    version: str,
    signing: MacSigning | None = None,
    *,
    windows_loader: Path | None = None,
    windows_webview: bool = False,
) -> list[Member]:
    instructions = stage / "README.txt"
    if windows_webview or windows_loader is not None:
        instructions.write_bytes(WINDOWS_PORTABLE_README.encode("utf-8"))
    else:
        instructions.write_bytes((PROJECT / "scripts" / "release-readme.txt").read_bytes())
    members = [Member(instructions.name, instructions)]
    match target.system:
        case "macos":
            members.extend(_mac_app(binary, stage, version, target, signing))
        case "windows":
            members.append(Member(f"{APP_NAME}.exe", binary, PERM_EXECUTABLE))
            if windows_loader is not None:
                members.append(Member(WINDOWS_LOADER_NAME, windows_loader))
        case "linux":
            members.append(Member("uninstallany", binary, PERM_EXECUTABLE))
    return sorted(members, key=lambda member: member.name)


def _write_zip(destination: Path, members: list[Member]) -> None:
    with zipfile.ZipFile(destination, "x", compression=zipfile.ZIP_DEFLATED) as archive:
        for member in members:
            info = zipfile.ZipInfo(member.name, ZIP_TIMESTAMP)
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | member.mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, member.path.read_bytes(), compresslevel=9)


def _write_tar(destination: Path, members: list[Member]) -> None:
    with (
        destination.open("xb") as stream,
        gzip.GzipFile(filename="", mode="wb", fileobj=stream, mtime=0) as compressed,
        tarfile.open(
            fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT
        ) as archive,
    ):
        for member in members:
            info = tarfile.TarInfo(member.name)
            info.mode = member.mode
            info.size = member.path.stat().st_size
            with member.path.open("rb") as source:
                archive.addfile(info, source)


def _verify_archive(destination: Path, members: list[Member], is_tar: bool) -> str:
    size = destination.stat().st_size
    if size >= MAX_ARCHIVE_BYTES:
        raise PackageError(f"{size:,} archive bytes. Required < {MAX_ARCHIVE_BYTES:,}.")
    if is_tar:
        with tarfile.open(destination, "r:gz") as archive:
            if archive.getnames() != [member.name for member in members]:
                raise PackageError("Archive members differ from the release manifest.")
            for member in members:
                entry = archive.getmember(member.name)
                source = archive.extractfile(entry)
                if source is None:
                    raise PackageError(f"Missing file: {member.name}")
                with source:
                    valid = (
                        entry.mode == member.mode
                        and source.read() == member.path.read_bytes()
                    )
                if not valid:
                    raise PackageError(f"Archive file differs: {member.name}")
    else:
        with zipfile.ZipFile(destination) as archive:
            if archive.namelist() != [member.name for member in members]:
                raise PackageError("Archive members differ from the release manifest.")
            for member in members:
                info = archive.getinfo(member.name)
                if stat.S_IMODE(info.external_attr >> 16) != member.mode:
                    raise PackageError(f"Archive permissions differ: {member.name}")
                if archive.read(info) != member.path.read_bytes():
                    raise PackageError(f"Archive content differs: {member.name}")
    with destination.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def _verify_signed_mac_archive(archive: Path, stage: Path, signing: MacSigning) -> None:
    extracted = stage / "verification"
    extracted.mkdir()
    # The entry set and file bytes were checked against the staged manifest.
    # Verify the actual ZIP round trip as well, including any stapled ticket.
    subprocess.run(
        ["/usr/bin/ditto", "-x", "-k", str(archive), str(extracted)], check=True
    )
    bundle = extracted / f"{APP_NAME}.app"
    _verify_developer_bundle(bundle)
    if signing.notary_profile is not None:
        subprocess.run(
            ["/usr/bin/xcrun", "stapler", "validate", str(bundle)], check=True
        )


def _publish(
    binary: Path,
    target: Target,
    version: str,
    output: Path,
    signing: MacSigning | None = None,
    *,
    windows_loader: Path | None = None,
    windows_webview: bool = False,
    cli: bool = False,
) -> Path:
    name = f"{APP_NAME}-CLI" if cli else APP_NAME
    stem = f"{name}-{version}-{target.system}-{target.arch}"
    is_tar = target.system == "linux"
    suffix = ".tar.gz" if is_tar else ".zip"
    published = output / stem
    output.mkdir(parents=True, exist_ok=True)
    if not binary.is_file():
        raise PackageError(f"Release executable not found: {binary}")
    if published.exists() or published.is_symlink():
        raise PackageError(
            f"Output already exists. Choose another --output-dir: {published}"
        )
    scratch = tempfile.TemporaryDirectory(prefix=".uninstallany-", dir=output)
    with scratch as temp:
        stage = Path(temp)
        delivery = stage / "delivery"
        delivery.mkdir()
        archive = delivery / f"{stem}{suffix}"
        # Validate the staged bytes, not a build path Cargo can replace later.
        staged_binary = stage / "binary"
        shutil.copyfile(binary, staged_binary)
        _validate_binary(staged_binary, target)
        staged_loader: Path | None = None
        if windows_loader is not None:
            staged_loader = stage / WINDOWS_LOADER_NAME
            shutil.copyfile(windows_loader, staged_loader)
            with staged_loader.open("rb") as source:
                _validate_windows_dll(source, target.machine)
        if cli:
            members = [
                Member("README.md", PROJECT / "docs" / "cli.md"),
                Member(CLI_BINARY, staged_binary, PERM_EXECUTABLE),
            ]
        else:
            members = _package_members(
                staged_binary,
                stage,
                target,
                version,
                signing,
                windows_loader=staged_loader,
                windows_webview=windows_webview,
            )
        if is_tar:
            _write_tar(archive, members)
        else:
            _write_zip(archive, members)
        checksum = _verify_archive(archive, members, is_tar)
        if signing is not None:
            _verify_signed_mac_archive(archive, stage, signing)
        (delivery / f"{archive.name}.sha256").write_bytes(
            f"{checksum}  {archive.name}\n".encode("ascii")
        )
        if published.exists() or published.is_symlink():
            raise PackageError(f"Output appeared during packaging: {published}")
        delivery.rename(published)
    return published / archive.name


def main() -> int:
    """Run the build, package validation and local publication."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=TARGETS)
    parser.add_argument("--cli", action="store_true", help="package the macOS or Linux CLI")
    parser.add_argument(
        "--binary", type=Path, help="package a trusted prebuilt release binary"
    )
    parser.add_argument(
        "--windows-loader",
        type=Path,
        help="trusted WebView2Loader.dll for a prebuilt Windows binary that imports it",
    )
    parser.add_argument("--output-dir", type=Path, default=PROJECT / "target" / "dist")
    parser.add_argument(
        "--macos-signing-identity", help="sign the macOS app and helper with Developer ID"
    )
    parser.add_argument(
        "--macos-helper-binary",
        type=Path,
        help="matching trusted helper for a feature-enabled macOS --binary input",
    )
    parser.add_argument(
        "--macos-notary-profile", help="notarize using a named Apple Keychain profile"
    )
    args = parser.parse_args()
    try:
        triple = args.target or _native_target()
        target = TARGETS[triple]
        if args.cli and target.system == "windows":
            raise PackageError("CLI packages are available for macOS and Linux.")
        if not args.cli and target.system == "macos" and platform.system() != "Darwin":
            raise PackageError("Creating and verifying an app seal requires macOS.")
        signing: MacSigning | None = None
        identity: str | None = args.macos_signing_identity
        supplied_helper: Path | None = args.macos_helper_binary
        notary_profile: str | None = args.macos_notary_profile
        binary_input: Path | None = args.binary
        windows_loader: Path | None = args.windows_loader
        if args.cli and any(
            value is not None for value in (identity, supplied_helper, notary_profile)
        ):
            raise PackageError("macOS bundle signing options apply to the desktop app.")
        if windows_loader is not None and (
            target.system != "windows" or binary_input is None
        ):
            raise PackageError("--windows-loader requires a Windows target and --binary.")
        if identity is not None:
            if target.system != "macos" or identity.strip() in ("", "-"):
                raise PackageError("Helper releases require a macOS Developer ID identity.")
            if notary_profile is not None and not notary_profile.strip():
                raise PackageError("The notarization Keychain profile must have a name.")
            if binary_input is None and supplied_helper is None:
                binary, helper = _signed_macos_build(triple, target)
            elif binary_input is not None and supplied_helper is not None:
                binary, helper = binary_input.resolve(), supplied_helper.resolve()
            else:
                raise PackageError(
                    "Pass --binary and --macos-helper-binary together for signed builds."
                )
            signing = MacSigning(identity, helper, notary_profile)
        else:
            if supplied_helper is not None or notary_profile is not None:
                raise PackageError(
                    "Helper binaries and notarization require --macos-signing-identity."
                )
            if binary_input is None:
                binary, windows_loader = _build(triple, target, cli=args.cli)
            else:
                binary = binary_input.resolve()
        output = args.output_dir.resolve()
        archive = _publish(
            binary,
            target,
            _project_version(),
            output,
            signing,
            windows_loader=windows_loader,
            windows_webview=target.system == "windows" and binary_input is None,
            cli=args.cli,
        )
    except (OSError, PackageError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Packaging failed: {error}\n")
    print(f"{archive} ({archive.stat().st_size:,} bytes)")
    print(archive.with_name(f"{archive.name}.sha256"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

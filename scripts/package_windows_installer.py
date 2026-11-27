#!/usr/bin/env python3
"""Build an unsigned x64 Windows MSI for disposable VM validation."""

from __future__ import annotations

import argparse
import hashlib
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Final
from xml.etree import ElementTree

from package_release import (
    APP_NAME,
    MAX_ARCHIVE_BYTES,
    PROJECT,
    TARGETS,
    PackageError,
    _project_version,
    _validate_pe,
    _validate_windows_dll,
)

SOURCE: Final = PROJECT / "scripts" / "windows-installer.wxs"
PORTABLE_TARGET: Final = TARGETS["x86_64-pc-windows-gnullvm"]
FOLDER_ID: Final = "ApplicationFolder"
FILES: Final = {
    "DesktopExecutable": "UninstallAny.exe",
    "PrivilegedHelper": "UninstallAnyHelper.exe",
    "WebView2Loader": "WebView2Loader.dll",
}
LOCK_TABLE: Final = "MsiLockPermissionsEx"
LOCK_COLUMNS: Final = (LOCK_TABLE, "LockObject", "Table", "SDDLText", "Condition")
# Use SID aliases so permissions do not depend on the Windows display language.
FOLDER_SDDL: Final = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)"
FILE_SDDL: Final = "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FRFX;;;BU)"
LOCK_ROWS: Final = (
    ("InstallDirectory", FOLDER_ID, "CreateFolder", FOLDER_SDDL, ""),
    *((name, name, "File", FILE_SDDL, "") for name in FILES),
)
COMPONENT_64BIT: Final = 0x100


def _tool(directory: Path, name: str) -> str:
    path = directory / name
    if not path.is_file():
        raise PackageError(f"Required MSI tool not found: {path}")
    return str(path)


def _run(tool: str, *args: str, cwd: Path) -> str:
    result = subprocess.run(
        [tool, *args], cwd=cwd, capture_output=True, text=True, check=False
    )
    if result.returncode:
        raise PackageError(result.stderr.strip() or result.stdout.strip() or tool)
    return result.stdout


def _permissions(stage: Path) -> Path:
    table = stage / f"{LOCK_TABLE}.idt"
    rows = (
        LOCK_COLUMNS,
        ("s72", "s72", "s32", "s0", "S255"),
        (LOCK_TABLE, LOCK_TABLE),
        *LOCK_ROWS,
    )
    table.write_bytes("".join("\t".join(row) + "\r\n" for row in rows).encode("ascii"))
    return table


def _read_table(info: str, msi: Path, table: str) -> list[dict[str, str]]:
    header, schema, name, *records = _run(
        info, "export", str(msi), table, cwd=msi.parent
    ).splitlines()
    if not schema or name.split("\t", 1)[0] != table:
        raise PackageError(f"Unexpected MSI table: {table}")
    columns = header.split("\t")
    return [dict(zip(columns, entry.split("\t"), strict=True)) for entry in records]


def _verify_inventory(info: str, msi: Path, product_code: str, version: str) -> None:
    table_names = set(_run(info, "tables", str(msi), cwd=msi.parent).splitlines())
    if "LockPermissions" in table_names:
        raise PackageError("The MSI contains incompatible legacy permissions.")
    if "CustomAction" in table_names and _read_table(info, msi, "CustomAction"):
        raise PackageError("The MSI contains unexpected custom actions.")
    properties = {
        row["Property"]: row["Value"] for row in _read_table(info, msi, "Property")
    }
    expected_properties = {
        "ALLUSERS": "1",
        "ProductCode": product_code,
        "ProductVersion": version,
    }
    if any(properties.get(name) != value for name, value in expected_properties.items()):
        raise PackageError("The MSI scope or product identity differs from the manifest.")
    summary = _run(info, "suminfo", str(msi), cwd=msi.parent)
    if not any(line.startswith("Template: x64;") for line in summary.splitlines()):
        raise PackageError("The MSI summary is missing its x64 architecture.")
    folders = {row["Directory"]: row for row in _read_table(info, msi, "Directory")}
    folder = folders.get(FOLDER_ID, {})
    if (
        folder.get("Directory_Parent") != "ProgramFiles64Folder"
        or folder.get("DefaultDir", "").rsplit("|", 1)[-1] != APP_NAME
    ):
        raise PackageError("The MSI does not install in the protected application folder.")
    created = _read_table(info, msi, "CreateFolder")
    if [row["Directory_"] for row in created] != [FOLDER_ID]:
        raise PackageError("The MSI does not declare its application directory.")
    actions = {
        row["Action"]: int(row["Sequence"])
        for row in _read_table(info, msi, "InstallExecuteSequence")
        if not row["Condition"]
    }
    # Windows Installer applies the folder and file ACLs during these actions.
    if not 0 < actions.get("CreateFolders", 0) < actions.get("InstallFiles", 0):
        raise PackageError("The MSI does not schedule folder and file installation.")
    components = {row["Component"]: row for row in _read_table(info, msi, "Component")}
    files = _read_table(info, msi, "File")
    if {row["File"]: row["FileName"].rsplit("|", 1)[-1] for row in files} != FILES:
        raise PackageError("The MSI file entries differ from the expected payloads.")
    if any(
        component["Directory_"] != FOLDER_ID
        or not int(component["Attributes"]) & COMPONENT_64BIT
        for component in components.values()
    ):
        raise PackageError("The MSI contains components outside its x64 install directory.")
    if any(row["Component_"] not in components for row in files):
        raise PackageError("The MSI file entries reference a missing component.")
    media = _read_table(info, msi, "Media")
    if len(media) != 1 or not media[0]["Cabinet"].startswith("#"):
        raise PackageError("The MSI must embed its complete payload cabinet.")
    permissions = _read_table(info, msi, LOCK_TABLE)
    actual = {tuple(row[column] for column in LOCK_COLUMNS) for row in permissions}
    if actual != set(LOCK_ROWS):
        raise PackageError("The MSI does not contain the expected file and directory ACLs.")


def _verify_payloads(extract: str, msi: Path, stage: Path) -> None:
    destination = stage / "extracted"
    destination.mkdir()
    _run(extract, "--directory", str(destination), str(msi), cwd=stage)
    files = sorted(path for path in destination.rglob("*") if path.is_file())
    if sorted(path.name for path in files) != sorted(FILES.values()):
        raise PackageError("Extracted MSI files differ from the staged file list.")
    for path in files:
        payload = stage / path.name
        if path.parent.name != APP_NAME or path.read_bytes() != payload.read_bytes():
            raise PackageError(f"MSI payload path or contents differ: {path.name}")


def _stage_payloads(stage: Path, paths: tuple[Path, Path, Path]) -> None:
    for name, source in zip(FILES.values(), paths, strict=True):
        destination = stage / name
        shutil.copyfile(source, destination)
        with destination.open("rb") as binary:
            validator = _validate_windows_dll if destination.suffix == ".dll" else _validate_pe
            validator(binary, PORTABLE_TARGET.machine)


def _publish(paths: tuple[Path, Path, Path], tools: Path, output: Path) -> Path:
    version = _project_version()
    product = ElementTree.parse(SOURCE).find("{*}Product")
    if product is None or product.get("Version") != version:
        raise PackageError("Update the Windows MSI product for the current project version.")
    code = product.attrib["Id"]
    stem = f"{APP_NAME}-{version}-windows-x64-unsigned-preview"
    published = output.resolve() / stem
    published.parent.mkdir(parents=True, exist_ok=True)
    if published.exists() or published.is_symlink():
        raise PackageError(f"Windows MSI output already exists: {published}")

    with tempfile.TemporaryDirectory(
        prefix=".windows-msi-", dir=published.parent
    ) as scratch:
        stage = Path(scratch)
        delivery = stage / "delivery"
        delivery.mkdir()
        msi = delivery / f"{stem}.msi"
        _stage_payloads(stage, paths)
        source = stage / SOURCE.name
        shutil.copyfile(SOURCE, source)
        _run(_tool(tools, "wixl"), "-a", "x64", "-o", str(msi), source.name, cwd=stage)
        table = _permissions(stage)
        _run(_tool(tools, "msibuild"), str(msi), "-i", table.name, cwd=stage)
        _verify_inventory(_tool(tools, "msiinfo"), msi, f"{{{code}}}", version)
        _verify_payloads(_tool(tools, "msiextract"), msi, stage)
        size = msi.stat().st_size
        if size >= MAX_ARCHIVE_BYTES:
            raise PackageError(f"{size:,} MSI bytes. Required < {MAX_ARCHIVE_BYTES:,}.")
        with msi.open("rb") as source_file:
            checksum = hashlib.file_digest(source_file, "sha256").hexdigest()
        msi.with_name(f"{msi.name}.sha256").write_bytes(
            f"{checksum}  {msi.name}\n".encode("ascii")
        )
        if published.exists() or published.is_symlink():
            raise PackageError(f"Windows MSI output appeared during packaging: {published}")
        delivery.rename(published)
    return published / msi.name


def main() -> int:
    """Package trusted local build inputs into a verified MSI preview."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gui", required=True, type=Path)
    parser.add_argument("--helper", required=True, type=Path)
    parser.add_argument("--loader", required=True, type=Path)
    parser.add_argument(
        "--tools-dir", required=True, type=Path, help="msitools bin directory"
    )
    parser.add_argument("--output-dir", type=Path, default=PROJECT / "target" / "dist")
    parser.add_argument("--unsigned-preview", required=True, action="store_true")
    arguments = parser.parse_args()
    try:
        paths = (arguments.gui, arguments.helper, arguments.loader)
        msi = _publish(paths, arguments.tools_dir.resolve(), arguments.output_dir)
    except (OSError, ValueError, KeyError, ElementTree.ParseError, PackageError) as error:
        parser.exit(1, f"Windows MSI packaging failed: {error}\n")
    print(msi)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

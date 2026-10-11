"""Read-only client inventory and PE/package inspection; never execute the target."""
import collections
import hashlib
import json
import math
from pathlib import Path
import shutil
import sys
import zipfile

sys.path.insert(0, str(Path(__file__).parent / "python-libs"))
import pefile

SOURCE = Path(r"F:\SOFTWARE\永恒之塔\aionclassic2")
CASE = Path(r"F:\RVE-Workspace\cases\aionclassic2-2026-10-10")
BACKUP = Path(__file__).parent / "aion-report-backup"
BACKUP.mkdir(exist_ok=True)


def save(name, value):
    text = json.dumps(value, ensure_ascii=False, indent=2)
    (CASE / "reports" / name).write_text(text, encoding="utf-8")
    (BACKUP / name).write_text(text, encoding="utf-8")


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def entropy(data):
    if not data:
        return 0
    return round(-sum((n / len(data)) * math.log2(n / len(data))
                      for n in collections.Counter(data).values()), 4)


def decoded(value):
    return value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)


files = []
groups = collections.defaultdict(lambda: {"files": 0, "bytes": 0})
for path in SOURCE.rglob("*"):
    if not path.is_file():
        continue
    stat = path.stat()
    relative = path.relative_to(SOURCE)
    files.append({"path": str(relative), "bytes": stat.st_size, "mtime_ns": stat.st_mtime_ns})
    group = relative.parts[0] if len(relative.parts) > 1 else "[root]"
    groups[group]["files"] += 1
    groups[group]["bytes"] += stat.st_size
save("client-inventory.json", {"source": str(SOURCE), "count": len(files),
                                "groups": dict(groups), "files": files})

pe_reports = []
for path in sorted((SOURCE / "bin64").iterdir()):
    if not path.is_file() or path.suffix.lower() not in (".dll", ".exe", ".bin"):
        continue
    with path.open("rb") as stream:
        if stream.read(2) != b"MZ":
            continue
    before = path.stat()
    record = {"path": str(path), "bytes": before.st_size, "sha256": digest(path)}
    try:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
        ])
        record.update(machine=hex(pe.FILE_HEADER.Machine),
                      entry_rva=hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                      image_base=hex(pe.OPTIONAL_HEADER.ImageBase),
                      linker_version=f"{pe.OPTIONAL_HEADER.MajorLinkerVersion}.{pe.OPTIONAL_HEADER.MinorLinkerVersion}",
                      coff_timestamp=pe.FILE_HEADER.TimeDateStamp,
                      sections=[{"name": decoded(s.Name.rstrip(b"\0")),
                                 "rva": hex(s.VirtualAddress), "virtual_size": s.Misc_VirtualSize,
                                 "raw_size": s.SizeOfRawData, "raw_offset": s.PointerToRawData,
                                 "flags": hex(s.Characteristics), "entropy": s.get_entropy()}
                                for s in pe.sections],
                      imports=[{"dll": decoded(d.dll), "count": len(d.imports),
                                "functions": [decoded(i.name) if i.name else f"ordinal:{i.ordinal}"
                                              for i in d.imports]}
                               for d in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])],
                      exports=[{"name": decoded(s.name) if s.name else None,
                                "rva": hex(s.address), "ordinal": s.ordinal}
                               for s in getattr(getattr(pe, "DIRECTORY_ENTRY_EXPORT", None), "symbols", [])],
                      overlay_start=pe.get_overlay_data_start_offset(),
                      warnings=pe.get_warnings())
        versions = {}
        for group in getattr(pe, "FileInfo", []):
            for entry in group:
                for table in getattr(entry, "StringTable", []):
                    versions.update({decoded(k): decoded(v) for k, v in table.entries.items()})
        record["version_info"] = versions
        if path.name in {"Aion.bin", "Game.dll", "ScriptDLL64.dll", "CrySystem.dll"}:
            target = CASE / "samples" / path.name
            if not target.exists():
                shutil.copy2(path, target)
            record["copy"] = str(target)
            record["copy_sha256"] = digest(target)
            record["copy_verified"] = record["copy_sha256"] == record["sha256"]
        pe.close()
    except Exception as error:
        record["error"] = f"{type(error).__name__}: {error}"
    after = path.stat()
    record["source_unchanged_during_read"] = (before.st_size, before.st_mtime_ns) == (after.st_size, after.st_mtime_ns)
    pe_reports.append(record)
save("pe-modules.json", pe_reports)

packages = []
for path in sorted(SOURCE.rglob("*.pak")):
    record = {"path": str(path.relative_to(SOURCE)), "bytes": path.stat().st_size}
    with path.open("rb") as stream:
        head = stream.read(4096)
        stream.seek(max(0, record["bytes"] - 128))
        tail = stream.read(128)
    record.update(head_hex=head[:32].hex(), tail_hex=tail[-32:].hex(),
                  head_entropy=entropy(head), standard_zip=zipfile.is_zipfile(path))
    if record["standard_zip"]:
        try:
            with zipfile.ZipFile(path) as package:
                entries = package.infolist()
                record["entries"] = [{"name": i.filename, "bytes": i.file_size,
                                       "compressed_bytes": i.compress_size,
                                       "method": i.compress_type, "flags": i.flag_bits}
                                      for i in entries]
                record["entry_count"] = len(entries)
        except Exception as error:
            record["zip_error"] = str(error)
    packages.append(record)
save("resource-packages.json", packages)

configs = []
for relative in ["LocalVersion.xml", "system.cfg", "cc.ini", "bin64/config.ini",
                 "LauncherConfigs/GameListConfig.xml", "LauncherConfigs/LauncherConfig.xml",
                 "LauncherConfigs/NewVersionCenter.ini"]:
    path = SOURCE / relative
    data = path.read_bytes()
    item = {"path": relative, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
            "head_hex": data[:32].hex(), "entropy": entropy(data)}
    if b"\0" not in data:
        try:
            item["utf8_text"] = data.decode("utf-8-sig")
        except UnicodeDecodeError:
            item["encoding"] = "not valid UTF-8; requires format inspection"
    configs.append(item)
save("configuration-files.json", configs)
print(json.dumps({"files": len(files), "groups": dict(groups),
                  "pe_modules": len(pe_reports), "pak_files": len(packages),
                  "standard_zip_packages": sum(x["standard_zip"] for x in packages),
                  "reports": str(CASE / "reports")}, ensure_ascii=False, indent=2))

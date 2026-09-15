#!/usr/bin/env python3
"""Bind Flower's ZIP, UPX-derived PE and independently decoded assets by SHA-256."""

from collections import Counter
from datetime import datetime
import hashlib
import json
from pathlib import Path
from zipfile import ZipFile

from unpack_flower import TABLE_RVA, read_entries


ROOT = Path(__file__).resolve().parents[1]
ZIP = ROOT / "demo-releases/prune_flower.zip"
UNPACKED = ROOT / "demo-unpack/prune_flower"
RELEASE = UNPACKED / "PRUNE_Flower"
PE = ROOT / "demo-derived/prune_flower/PRUNE_Flower.unpacked.exe"
GCR = RELEASE / "PRUNE_Flower.gcr"
ASSETS = ROOT / "demo-assets/prune_flower"
OUTPUT = ROOT / "documentation/flower-manifest.json"


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def file_record(path):
    data = path.read_bytes()
    return {"path": path.relative_to(ROOT).as_posix(),
            "size": len(data), "sha256": sha256(data)}


def main():
    zip_entries = []
    with ZipFile(ZIP) as archive:
        for info in archive.infolist():
            data = archive.read(info)
            target = UNPACKED / info.filename
            if info.is_dir():
                if not target.is_dir():
                    raise ValueError(f"missing ZIP directory: {info.filename}")
            elif target.read_bytes() != data:
                raise ValueError(f"expanded ZIP mismatch: {info.filename}")
            zip_entries.append({
                "path": info.filename, "directory": info.is_dir(),
                "size": info.file_size, "compressed_size": info.compress_size,
                "crc32": f"{info.CRC:08x}", "sha256": sha256(data),
                "zip_timestamp": datetime(*info.date_time).isoformat(sep=" "),
            })
    archive = GCR.read_bytes()
    entries = read_entries(archive, PE.read_bytes())
    found = {p.relative_to(ASSETS).as_posix() for p in ASSETS.rglob("*") if p.is_file()}
    if found != {entry.path.as_posix() for entry in entries}:
        raise ValueError("recovered asset set does not match the executable table")
    result = []
    for entry in entries:
        payload = entry.decode(archive)
        if (ASSETS / entry.path).read_bytes() != payload:
            raise ValueError(f"C/Python decoded payload mismatch: {entry.name}")
        result.append({
            "original_path": entry.name, "path": entry.path.as_posix(),
            "record_offset": entry.record_offset, "record_size": entry.record_size,
            "payload_offset": entry.payload_offset, "stored_size": entry.stored_size,
            "size": entry.size, "method": entry.method, "sha256": sha256(payload),
        })
    manifest = {
        "schema_version": 1,
        "title": "Flower by Prune: asset extraction manifest",
        "distribution": {**file_record(ZIP), "entries": zip_entries},
        "derived_executable": {
            **file_record(PE),
            "source": file_record(RELEASE / "PRUNE_Flower.exe"),
            "operation": "UPX 5.1.1 win64: upx -d -o <derived> <original>",
            "note": "Derived analysis file; the packed release PE is preserved separately.",
        },
        "container": {
            **file_record(GCR),
            "format": "Flower GCR external-table LZARI",
            "metadata_executable": PE.relative_to(ROOT).as_posix(),
            "metadata_table_rva": f"0x{TABLE_RVA:08x}",
            "metadata_table_raw_offset": "0x0003f810",
            "entry_size": 12, "file_count": len(entries),
            "total_size": sum(e.size for e in entries),
            "stored_payload_bytes": sum(e.stored_size for e in entries),
            "record_prefix_bytes": len(entries) * 4,
            "unaccounted_bytes": len(archive) - sum(e.record_size for e in entries),
            "filename_encoding": "Windows-1252",
            "path_mapping": "C:/PRUNE_Flower/ becomes C/PRUNE_Flower/ under the output root",
            "extensions": dict(sorted(Counter(e.path.suffix.lower() for e in entries).items())),
            "methods": dict(Counter(e.method for e in entries)),
            "entries": result,
        },
        "standalone_soundtrack": file_record(RELEASE / "PRUNE_Flower.mp3"),
        "verification": "All 81 C outputs independently decoded in Python and compared byte for byte.",
    }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Wrote {OUTPUT}: {len(entries)} verified files, {sum(e.size for e in entries):,} bytes")


if __name__ == "__main__":
    main()

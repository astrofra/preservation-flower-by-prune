#!/usr/bin/env python3
"""Check Flower's preservation layers, both decoders, and recovered asset formats."""

from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile
import unittest
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]
TOOL = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else ROOT / "bin/klx_unpack.exe"
if len(sys.argv) > 1:
    del sys.argv[1]
sys.path.insert(0, str(ROOT / "tools"))
from build_manifest import ASSETS, GCR, PE, RELEASE, UNPACKED, ZIP, sha256
from unpack_flower import FormatError, TABLE_RVA, read_entries


class FlowerAssetsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads((ROOT / "documentation/flower-manifest.json").read_text(encoding="utf-8"))
        cls.entries = cls.manifest["container"]["entries"]

    def run_tool(self, *arguments, success=True):
        result = subprocess.run([str(TOOL), *map(str, arguments)], capture_output=True,
                                text=True, encoding="utf-8", errors="replace", timeout=60)
        self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
        return result

    def check_record(self, record):
        data = (ROOT / record["path"]).read_bytes()
        self.assertEqual(len(data), record["size"])
        self.assertEqual(sha256(data), record["sha256"])

    def test_source_layers(self):
        for key in ("distribution", "derived_executable", "container", "standalone_soundtrack"):
            self.check_record(self.manifest[key])
        self.check_record(self.manifest["derived_executable"]["source"])
        expected = {e["path"]: e for e in self.manifest["distribution"]["entries"]}
        with ZipFile(ZIP) as archive:
            self.assertEqual(set(archive.namelist()), set(expected))
            for info in archive.infolist():
                target = UNPACKED / info.filename
                if info.is_dir():
                    self.assertTrue(target.is_dir())
                else:
                    self.assertEqual(archive.read(info), target.read_bytes(), info.filename)
                    self.assertEqual(sha256(target.read_bytes()), expected[info.filename]["sha256"])

    def test_recovered_inventory(self):
        found = {p.relative_to(ASSETS).as_posix(): p for p in ASSETS.rglob("*") if p.is_file()}
        self.assertEqual(set(found), {e["path"] for e in self.entries})
        self.assertEqual(len(found), 81)
        self.assertEqual(sum(p.stat().st_size for p in found.values()), 1_796_779)
        self.assertEqual(Counter(p.suffix.lower() for p in found.values()),
                         Counter({".lwo": 35, ".lws": 13, ".jpg": 33}))
        for entry in self.entries:
            data = found[entry["path"]].read_bytes()
            self.assertEqual(len(data), entry["size"], entry["path"])
            self.assertEqual(sha256(data), entry["sha256"], entry["path"])

    def test_lightwave_structures_and_scene_objects(self):
        known = {e["path"].casefold() for e in self.entries}
        for entry in self.entries:
            p = ASSETS / entry["path"]
            data = p.read_bytes()
            if p.suffix.lower() == ".lwo":
                self.assertEqual(data[:4], b"FORM", p)
                self.assertEqual(data[8:12], b"LWO2", p)
                self.assertEqual(struct.unpack_from(">I", data, 4)[0] + 8, len(data), p)
                offset = 12
                tags = set()
                while offset < len(data):
                    self.assertLessEqual(offset + 8, len(data), p)
                    tag = data[offset:offset + 4]
                    tags.add(tag)
                    size = struct.unpack_from(">I", data, offset + 4)[0]
                    if tag == b"PNTS":
                        self.assertEqual(size % 12, 0, p)
                    offset += 8 + size + (size & 1)
                    self.assertLessEqual(offset, len(data), p)
                self.assertEqual(offset, len(data), p)
                self.assertTrue({b"PNTS", b"POLS", b"SURF"}.issubset(tags), p)
            elif p.suffix.lower() == ".lws":
                self.assertTrue(data.startswith(b"LWSC\r\n3\r\n"), p)
                references = re.findall(r"^LoadObjectLayer \d+ (.+)$", data.decode("cp1252"), re.M)
                self.assertTrue(references, p)
                for reference in references:
                    # Preserve files unchanged; normalize only for this lookup.
                    key = reference.strip().replace("\\", "/").replace(":", "/").casefold()
                    self.assertIn(key, known, f"{p}: {reference}")

    def test_jpeg_decode(self):
        try:
            from PIL import Image
        except ImportError:
            self.skipTest("Pillow is needed for full JPEG decode")
        for entry in self.entries:
            p = ASSETS / entry["path"]
            if p.suffix.lower() == ".jpg":
                with Image.open(p) as image:
                    self.assertEqual(image.format, "JPEG", p)
                    image.load()
                    self.assertGreater(image.width * image.height, 0, p)

    def test_python_decoder(self):
        archive = GCR.read_bytes()
        entries = read_entries(archive, PE.read_bytes())
        self.assertEqual(len(entries), len(self.entries))
        for entry, expected in zip(entries, self.entries):
            self.assertEqual(entry.name, expected["original_path"])
            self.assertEqual(sha256(entry.decode(archive)), expected["sha256"], entry.name)

    def test_c_decoder_and_overwrite_refusal(self):
        listing = self.run_tool("--list", "--flower-exe", PE, GCR)
        self.assertTrue(listing.stdout.rstrip().endswith("81 files"))
        with tempfile.TemporaryDirectory(prefix="flower-extract-") as temporary:
            output = Path(temporary) / "assets"
            self.run_tool("--flower-exe", PE, GCR, output)
            actual = {p.relative_to(output).as_posix() for p in output.rglob("*") if p.is_file()}
            self.assertEqual(actual, {e["path"] for e in self.entries})
            for entry in self.entries:
                self.assertEqual(sha256((output / entry["path"]).read_bytes()), entry["sha256"])
            self.run_tool("--flower-exe", PE, GCR, output, success=False)

    def test_reject_packed_exe_and_truncated_archive(self):
        packed = RELEASE / "PRUNE_Flower.exe"
        with self.assertRaises(FormatError):
            read_entries(GCR.read_bytes(), packed.read_bytes())
        with tempfile.TemporaryDirectory(prefix="flower-invalid-") as temporary:
            output = Path(temporary) / "output"
            self.run_tool("--flower-exe", packed, GCR, output, success=False)
            self.assertFalse(output.exists())
            broken = Path(temporary) / "truncated.gcr"
            broken.write_bytes(GCR.read_bytes()[:-1])
            with self.assertRaises(FormatError):
                read_entries(broken.read_bytes(), PE.read_bytes())
            self.run_tool("--flower-exe", PE, broken, output, success=False)
            self.assertFalse(output.exists())

    def test_reject_unsafe_metadata_path(self):
        executable = bytearray(PE.read_bytes())
        # The UPX-derived image has raw offset == RVA in this section.
        pointer = struct.unpack_from("<I", executable, TABLE_RVA)[0] - 0x400000
        bad_name = b"C:/PRUNE_Flower/../escape.JPG\0"
        executable[pointer:pointer + len(bad_name)] = bad_name
        with self.assertRaises(FormatError):
            read_entries(GCR.read_bytes(), executable)
        with tempfile.TemporaryDirectory(prefix="flower-path-") as temporary:
            bad_pe = Path(temporary) / "bad.exe"
            bad_pe.write_bytes(executable)
            output = Path(temporary) / "output"
            self.run_tool("--flower-exe", bad_pe, GCR, output, success=False)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)

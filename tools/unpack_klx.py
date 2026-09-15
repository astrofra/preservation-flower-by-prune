#!/usr/bin/env python3
"""Extract an nX/nXng FXLK archive. Python 3.10+, no dependencies.

The LZARI decoder was reconstructed during the FreeStyle preservation effort
and is reused by the related external-table extractor for Flower. Archive
drive prefixes are retained as ordinary directories below the output root.
"""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import struct
import sys


class FormatError(ValueError):
    """An unsupported or inconsistent archive."""


class LzariDecoder:
    N = 4096
    F = 60
    SYMBOLS = 314
    Q1 = 0x8000
    Q2 = 0x10000
    Q3 = 0x18000
    Q4 = 0x20000

    def __init__(self, data: bytes):
        self.data = data
        self.bit_position = 0
        self.low, self.high, self.value = 0, self.Q4, 0
        self.window = bytearray(b" " * (self.N - self.F) + b"\0" * self.F)
        self.frequencies = [0] + [1] * self.SYMBOLS
        self.cumulative = list(range(self.SYMBOLS, -1, -1))
        self.symbol_to_char = [0] + list(range(self.SYMBOLS))
        self.positions = [0] * (self.N + 1)
        for i in range(self.N, 0, -1):
            self.positions[i - 1] = self.positions[i] + 10000 // (i + 200)

    def bit(self) -> int:
        offset, shift = divmod(self.bit_position, 8)
        self.bit_position += 1
        if offset >= len(self.data):
            # Arithmetic termination needs a little zero-bit lookahead.
            if offset >= len(self.data) + 2:
                raise FormatError("truncated LZARI stream")
            return 0
        return (self.data[offset] >> (7 - shift)) & 1

    def symbol(self, cumulative: list[int]) -> int:
        width = self.high - self.low
        if width <= 0 or not self.low <= self.value < self.high:
            raise FormatError("invalid arithmetic coding interval")
        value = ((self.value - self.low + 1) * cumulative[0] - 1) // width
        left, right = 1, len(cumulative) - 1
        while left < right:
            middle = (left + right) // 2
            if cumulative[middle] > value:
                left = middle + 1
            else:
                right = middle
        symbol = left
        self.high = self.low + width * cumulative[symbol - 1] // cumulative[0]
        self.low += width * cumulative[symbol] // cumulative[0]
        while True:
            if self.low >= self.Q2:
                self.low -= self.Q2
                self.high -= self.Q2
                self.value -= self.Q2
            elif self.low >= self.Q1 and self.high <= self.Q3:
                self.low -= self.Q1
                self.high -= self.Q1
                self.value -= self.Q1
            elif self.high > self.Q2:
                break
            self.low *= 2
            self.high *= 2
            self.value = self.value * 2 + self.bit()
        return symbol

    def update(self, symbol: int) -> None:
        if self.cumulative[0] >= 0x7FFF:
            total = 0
            for i in range(self.SYMBOLS, 0, -1):
                self.cumulative[i] = total
                self.frequencies[i] = (self.frequencies[i] + 1) // 2
                total += self.frequencies[i]
            self.cumulative[0] = total
        i = symbol
        while self.frequencies[i] == self.frequencies[i - 1]:
            i -= 1
        if i != symbol:
            self.symbol_to_char[i], self.symbol_to_char[symbol] = (
                self.symbol_to_char[symbol], self.symbol_to_char[i]
            )
        self.frequencies[i] += 1
        for j in range(i):
            self.cumulative[j] += 1

    def decode(self, size: int) -> bytes:
        if size == 0:
            return b""
        for _ in range(17):
            self.value = self.value * 2 + self.bit()
        output = bytearray()
        cursor = self.N - self.F
        while len(output) < size:
            symbol = self.symbol(self.cumulative)
            char = self.symbol_to_char[symbol]
            self.update(symbol)
            if char < 256:
                output.append(char)
                self.window[cursor] = char
                cursor = (cursor + 1) & (self.N - 1)
            else:
                distance = self.symbol(self.positions)
                source = (cursor - distance) & (self.N - 1)
                length = char - 253
                if len(output) + length > size:
                    raise FormatError("LZARI match exceeds declared output size")
                for i in range(length):
                    char = self.window[(source + i) & (self.N - 1)]
                    output.append(char)
                    self.window[cursor] = char
                    cursor = (cursor + 1) & (self.N - 1)
        return bytes(output)


@dataclass(frozen=True)
class Entry:
    name: str
    size: int
    stored_size: int
    offset: int

    @property
    def method(self) -> str:
        return "xor-9a" if self.size == self.stored_size else "lzari"

    def decode(self, archive: bytes) -> bytes:
        payload = archive[self.offset:self.offset + self.stored_size]
        if self.method == "xor-9a":
            return bytes(byte ^ 0x9A for byte in payload)
        try:
            return LzariDecoder(payload).decode(self.size)
        except FormatError as exc:
            raise FormatError(f"{self.name}: {exc}") from exc


def read_archive(
    data: bytes, max_bytes: int = 256 * 1024 * 1024
) -> tuple[list[Entry], bytes]:
    if len(data) < 12 or data[:4] != b"FXLK":
        raise FormatError("expected a 12-byte FXLK header")
    index_size, stored_index_size = struct.unpack_from("<II", data, 4)
    offset = 12 + stored_index_size
    if not 0 < index_size <= max_bytes or not 0 < stored_index_size <= len(data) - 12:
        raise FormatError("invalid index sizes")
    index = LzariDecoder(data[12:offset]).decode(index_size)
    entries = []
    cursor = total = 0
    while cursor < len(index):
        end = index.find(b"\0", cursor)
        if end <= cursor or end + 9 > len(index):
            raise FormatError("invalid index entry")
        name = index[cursor:end].decode("cp1252")
        size, stored_size = struct.unpack_from("<II", index, end + 1)
        cursor = end + 9
        total += size
        if total > max_bytes:
            raise FormatError("declared output exceeds --max-output-mib")
        if offset + stored_size > len(data) or (size and not stored_size):
            raise FormatError(f"invalid payload size for {name}")
        entries.append(Entry(name, size, stored_size, offset))
        offset += stored_size
    if offset != len(data):
        raise FormatError(f"unaccounted archive bytes: {len(data) - offset}")
    return entries, index


def relative_path(name: str) -> Path:
    name = name.replace("\\", "/")
    if re.match(r"^[A-Za-z]:/", name):
        name = name[0].upper() + name[2:]
    parts = name.split("/")
    for part in parts:
        if (
            not part
            or part in (".", "..")
            or part.endswith((".", " "))
            or any(ord(char) < 32 or char in '<>:"|?*' for char in part)
            or re.fullmatch(
                r"(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?", part
            )
        ):
            raise FormatError(f"unsafe output path: {name!r}")
    return Path(*parts)


def extract(data: bytes, entries: list[Entry], output: Path, archive_name: str) -> None:
    output = output.resolve()
    targets = []
    seen = {"manifest.json"}
    for entry in entries:
        relative = relative_path(entry.name)
        key = relative.as_posix().casefold()
        if key in seen:
            raise FormatError(f"duplicate output path: {relative}")
        seen.add(key)
        target = output / relative
        if not target.resolve().is_relative_to(output):
            raise FormatError(f"output path escapes destination: {relative}")
        if target.exists():
            raise FileExistsError(f"refusing to overwrite {target}")
        targets.append((entry, relative, target))
    manifest_path = output / "manifest.json"
    if manifest_path.exists():
        raise FileExistsError(f"refusing to overwrite {manifest_path}")
    decoded = [
        (entry, relative, target, entry.decode(data))
        for entry, relative, target in targets
    ]
    manifest = {
        "archive": archive_name,
        "archive_sha256": hashlib.sha256(data).hexdigest(),
        "archive_size": len(data),
        "format": "FXLK / KLX",
        "filename_encoding": "Windows-1252",
        "path_mapping": "drive identity retained as an ordinary directory",
        "file_count": len(entries),
        "total_size": sum(entry.size for entry in entries),
        "entries": [],
    }
    for entry, relative, target, payload in decoded:
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(payload)
        manifest["entries"].append(
            {
                "original_path": entry.name,
                "path": relative.as_posix(),
                "size": entry.size,
                "stored_size": entry.stored_size,
                "offset": entry.offset,
                "method": entry.method,
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    output.mkdir(parents=True, exist_ok=True)
    with manifest_path.open("x", encoding="utf-8") as stream:
        json.dump(manifest, stream, indent=2, ensure_ascii=False)
        stream.write("\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("output", nargs="?", type=Path, help="new extraction directory")
    parser.add_argument("--list", action="store_true", help="list entries without extracting")
    parser.add_argument(
        "--max-output-mib", type=int, default=256,
        help="decoded size limit (default: 256)",
    )
    args = parser.parse_args()
    if not args.list and args.output is None:
        parser.error("provide an output directory or --list")
    if args.max_output_mib <= 0:
        parser.error("--max-output-mib must be positive")
    try:
        data = args.archive.read_bytes()
        entries, _ = read_archive(data, args.max_output_mib * 1024 * 1024)
        if args.list:
            for entry in entries:
                print(
                    f"{entry.offset:9d} {entry.stored_size:9d} {entry.size:9d} "
                    f"{entry.method:7s} {entry.name}"
                )
        else:
            extract(data, entries, args.output, str(args.archive))
            print(f"Extracted to {args.output.resolve()}")
        counts = Counter(Path(entry.name).suffix.lower() for entry in entries)
        print(
            f"{len(entries)} files, {sum(entry.size for entry in entries):,} "
            f"decoded bytes; {dict(sorted(counts.items()))}"
        )
        return 0
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

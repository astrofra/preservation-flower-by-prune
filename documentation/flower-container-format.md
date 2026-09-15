# Flower GCR external-table format

## Result and relationship to Dash

The inspected release uses the same record layout and LZARI variant as
`S:/works/preservation-dash-by-condense`. Its `.gcr` extension still denotes
a stream whose filenames and record sizes are compiled into the executable.
It does not have the self-contained FXLK index supported by the inherited
`klx_unpack.c` tool.

Only the executable-table location, entry count, and accepted authoring root
needed a new native extractor mode. No compression-code changes were needed.
These observations apply to the exact artifacts recorded in
[`flower-manifest.json`](flower-manifest.json).

| Property | Dash | Flower |
|---|---|---|
| Executable in release | Unpacked PE32 | UPX-packed PE32 |
| Table RVA | `0x17030` | `0x3f810` after UPX decompression |
| Entries | 98 | 81 |
| Entry layout | Three little-endian 32-bit words | Same |
| Authoring root | `D:/vrac/` | `C:/PRUNE_Flower/` |
| GCR record | Decoded size + LZARI bytes | Same |
| Objects | 28 `LWOB` | 35 `LWO2` |
| Scenes | 4 `LWSC` version 1 | 13 `LWSC` version 3 |
| Images | 63 TGA | 33 JPEG |
| Other container files | 3 PRK | None |

## Executable metadata

`PRUNE_Flower.exe` is 204,800 bytes and contains `UPX0` and `UPX1` sections.
UPX 5.1.1 reconstructs a 483,328-byte PE32 file, preserved in `demo-derived/`.
Its image base is `0x00400000`.

| Field | Value |
|---|---:|
| Table RVA / derived PE raw offset | `0x0003f810` |
| Table VA | `0x0043f810` |
| Number of entries | 81 |
| Entry size | 12 bytes |
| Table byte size | 972 |
| Table end, exclusive | RVA `0x0003fbdc` |

Each table entry has this layout:

| Offset | Meaning |
|---|---|
| `+0` | Absolute VA of a NUL-terminated Windows-1252 filename |
| `+4` | Compression flag; all 81 release entries contain `1` |
| `+8` | Complete GCR record size, including the four-byte decoded-size prefix |

Static disassembly independently confirms the table extent. At VA
`0x004137ff`, the lookup code loads `EBP = 0x0043f818`, the first size field.
It reads the path from `[EBP-8]` at `0x0041381d`, adds `[EBP]` to the archive
offset at `0x0041388f`–`0x00413896`, increments EBP by 12 at `0x00413898`, and
compares it with `0x0043fbe4` at `0x0041389c`.
Thus `(0x43fbe4 - 0x43f818) / 12 = 81` records. At `0x004138c8`, the matched
entry's compression flag is read from the table's second field.

## GCR record stream

Records are concatenated in table order, without alignment padding:

| Record offset | Size | Meaning |
|---|---:|---|
| `+0` | 4 | Decoded payload length, unsigned little-endian |
| `+4` | Table record size minus 4 | Headerless LZARI payload |

| Accounting | Bytes |
|---|---:|
| Entire GCR | 1,554,078 |
| 81 decoded-size prefixes | 324 |
| Compressed payloads | 1,553,754 |
| Decoded payloads | 1,796,779 |
| Unaccounted bytes | 0 |

The first record is `C:/PRUNE_Flower/Images/sky/skyWarp__up.JPG`. It has
record size 8,213, compressed size 8,209, and decoded size 8,872. The first
GCR bytes are `a8 22 00 00 2f 8a 04 39`. Decoding yields a complete 512 × 512
JPEG beginning with `ff d8 ff e0` and the JFIF identifier.

## LZARI codec

The inherited Dash/FreeStyle decoder works unchanged:

- 4,096-byte sliding window, initialized with 4,036 spaces and 60 zero bytes;
- literals 0–255 and match lengths 3–60, represented by 314 adaptive symbols;
- arithmetic interval `[0, 0x20000)` and 17 initial code bits;
- most-significant-bit-first input;
- frequencies initially one, rescaled at cumulative total `0x7fff`;
- distance cumulative model `c[i-1] = c[i] + 10000 // (i + 200)`;
- decoded size as the terminator, with at most two zero-byte lookahead bytes.

Both implementations consume every record with its own bounded compressed
slice. All 81 output paths, lengths, and SHA-256 values agree.

## Preservation limits

GCR has no internal filenames, timestamps, or checksums. Recovery depends on
the matching executable table; the external SHA-256 manifest binds the ZIP,
packed PE, derived PE, GCR, and decoded files together. This is evidence of
container/codec compatibility, not a claim that Flower's entire engine is
identical to Dash's. The original demo was not executed during extraction.

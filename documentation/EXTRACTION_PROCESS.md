# Flower extraction process

## Preserved layers

| Layer | Location |
|---|---|
| Untouched distribution | `demo-releases/prune_flower.zip` |
| Six original ZIP file payloads | `demo-unpack/prune_flower/` |
| UPX-derived metadata executable | `demo-derived/prune_flower/PRUNE_Flower.unpacked.exe` |
| 81 original decoded assets | `demo-assets/prune_flower/C/PRUNE_Flower/` |
| Native extractor | `klx_unpack.c`, `bin/klx_unpack.exe` |
| Independent Python extractor | `tools/unpack_flower.py`, `tools/unpack_klx.py` |
| Provenance and per-file hashes | `documentation/flower-manifest.json` |
| Verification | `tests/validate_assets.py` |

The source ZIP is 3,552,422 bytes, SHA-256:

```text
664b2a5c468f975a904a74c9d3296940cfa3f4709aca3d84a5cd21aabb016e47
```

## 1. Expand the ordinary ZIP layer

The supplied filename on disk is `demo-releases/prune_flower.zip`. The ZIP
contains six files and one directory entry. Paths were checked for traversal,
absolute names, and duplicates before expansion. Each resulting file was
compared byte for byte with its ZIP payload.

For a fresh checkout without the expanded files:

```powershell
python -m zipfile -e demo-releases/prune_flower.zip demo-unpack/prune_flower
```

ZIP central-directory timestamps, CRC-32, sizes, and SHA-256 hashes are in the
manifest. ZIP timestamps have no timezone; filesystem extraction times are
not used as historical evidence.

## 2. Recover executable metadata without running the demo

The release PE is UPX-packed. Its table is unavailable to the ordinary PE
reader until decompressed. UPX 5.1.1 was already installed locally:

```powershell
New-Item -ItemType Directory -Path demo-derived/prune_flower
upx -d -o demo-derived/prune_flower/PRUNE_Flower.unpacked.exe `
    demo-unpack/prune_flower/PRUNE_Flower/PRUNE_Flower.exe
```

The derived file is 483,328 bytes, SHA-256:

```text
09bb8b3b40bf464a409da7b236f99d40f96c234e69783ed27d12ddef98427317
```

The original packed executable remains unchanged in `demo-unpack/`.
The derived PE is retained separately so extraction does not require UPX on
every machine. The manifest records the transformation and both PE hashes.

## 3. Compare against Dash

The Dash documentation and decoders supplied the initial hypothesis:
12-byte table entries in the PE, decoded-size prefixes in GCR, and LZARI.
A trial decode of Flower's first record produced a valid JPEG.

After UPX decompression, 81 consecutive metadata entries were located at
RVA `0x3f810`. The executable lookup loop independently confirms the count;
the sum of record sizes is exactly the entire GCR length. Details and
instruction addresses are in [the format description](flower-container-format.md).

## 4. Extract and cross-check

The existing native extractor gained `--flower-exe` with the recovered table
constants. Its PE parser, path checks, and LZARI decoder were reused unchanged.
The Python Dash reader was adapted independently with the same metadata
constants. Both retain `C:` as the ordinary output directory `C/`.

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
./bin/klx_unpack.exe --flower-exe `
    demo-derived/prune_flower/PRUNE_Flower.unpacked.exe `
    demo-unpack/prune_flower/PRUNE_Flower/PRUNE_Flower.gcr `
    demo-assets/prune_flower
```

Destinations must be new. The preservation run used MSVC 19.41 with `/W4 /WX`
and the static Microsoft runtime. Independent Python extraction:

```powershell
python tools/unpack_flower.py `
    demo-derived/prune_flower/PRUNE_Flower.unpacked.exe `
    demo-unpack/prune_flower/PRUNE_Flower/PRUNE_Flower.gcr `
    analysis/python-extraction
python tools/build_manifest.py
ctest --test-dir build -C Release --output-on-failure
```

The manifest builder repeats the Python decode and refuses to produce the
manifest if any native output differs. All 81 files agree byte for byte.
The tests additionally check original ZIP payloads, preserved hashes, IFF
structures, scene object references, JPEG decoding, rejection of packed PE
input, truncation, unsafe paths, and existing destinations.

## 5. Preserve original content and document authoring references

All output payload bytes, filename case, and scene line endings are retained.
`.gitattributes` disables text normalization for the four preservation layers.
The MP3 soundtrack is already an ordinary ZIP entry and is preserved there.

The recovered files use `LWO2`, `LWSC` version 3, and JPEG. Historical paths
inside LightWave files are untouched. Missing or outdated texture references
are listed in [the validation report](ASSET_VALIDATION.md); no replacement
textures or rewritten scenes were introduced.

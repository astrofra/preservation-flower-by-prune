# Preservation of Flower by Prune

Assets recovered from **Flower**, released by Prune at Synthesis in February
2001. The release credits No Recess and Stil for code, Med for music, and
Neurox for 3D.

The extracted assets are in [`demo-assets/prune_flower/C/PRUNE_Flower/`](demo-assets/prune_flower/C/PRUNE_Flower/):

| Directory | Recovered files |
|---|---:|
| [Objects](demo-assets/prune_flower/C/PRUNE_Flower/Objects/) | 35 LightWave `LWO2` objects |
| [Scenes](demo-assets/prune_flower/C/PRUNE_Flower/Scenes/) | 13 LightWave `LWSC` version 3 scenes |
| [Images](demo-assets/prune_flower/C/PRUNE_Flower/Images/) | 33 JPEG textures/images |

All 81 payloads (1,796,779 bytes) were extracted unchanged and independently
verified with C and Python decoders. The standalone MP3 remains in
[`demo-unpack/prune_flower/PRUNE_Flower/`](demo-unpack/prune_flower/PRUNE_Flower/).

**Comparison with Dash:** the external executable table, GCR record layout,
and LZARI compression are unchanged. Flower uses an UPX-packed executable,
`LWO2` objects, version 3 scenes, and JPEG images, where Dash used `LWOB`,
version 1 scenes, and TGA images.

Original scene and texture references are preserved. To reopen them in a 3D
editor, set the content directory to the recovered `C/PRUNE_Flower` folder
and relink historical paths as needed. Many object references still end in
`.tga`; their corresponding recovered images end in `.jpg`. Two old image
references have no counterpart in this release; see the
[validation report](documentation/ASSET_VALIDATION.md).

## Reproduce the extraction

The UPX-derived metadata executable is included separately from the original
release. On Windows:

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
./bin/klx_unpack.exe --flower-exe `
    demo-derived/prune_flower/PRUNE_Flower.unpacked.exe `
    demo-unpack/prune_flower/PRUNE_Flower/PRUNE_Flower.gcr `
    demo-assets/another-extraction
ctest --test-dir build -C Release --output-on-failure
```

The extraction destination must be new. Python 3.10+ runs the verification;
Pillow enables the full JPEG decoding check. The extractor itself has no
third-party dependencies.

See the [extraction process](documentation/EXTRACTION_PROCESS.md),
[container format](documentation/flower-container-format.md), and
[SHA-256 manifest](documentation/flower-manifest.json).

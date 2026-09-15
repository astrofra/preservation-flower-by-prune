# Flower asset validation

## Results

| Check | Result |
|---|---|
| Original ZIP expansion | All six file payloads match the ZIP byte for byte |
| GCR byte accounting | 81 records cover all 1,554,078 bytes |
| C versus Python decode | 81/81 paths, sizes and SHA-256 hashes match |
| Recovered bytes | 1,796,779 |
| LightWave objects | 35 complete `FORM/LWO2` files |
| LightWave scenes | 13 `LWSC` version 3 text files |
| Scene object references | All 69 `LoadObjectLayer` references resolve after path normalization |
| Images | All 33 JPEG files fully decoded with Pillow |

Object validation checks FORM length, all top-level IFF chunk boundaries,
point-data alignment, and the presence of point, polygon, and surface chunks.
Scene files retain their original CRLF line endings and historical paths.
JPEG dimensions range from 32 × 32 to 2048 × 64, including 640 × 480 and
800 × 600 full-screen images.

## Texture references when reopening in an editor

The original object `CLIP/STIL` image references include 33 occurrences
(29 distinct paths). With case-insensitive matching and the historical
`C:PRUNE_Flower/` prefix normalized for lookup:

- 8 occurrences directly match recovered JPEG paths;
- 23 reference `.tga` filenames whose same-path `.jpg` counterparts exist;
- 2 point to files absent from this release.

The two unmatched references are:

| Object | Original image reference |
|---|---|
| `sollw5.lwo` | `C:Flower/Images/solBAKKER.tga` |
| `Toroid.lwo` | `C:JfyeIIDemo/Images/didiou.TGA` |

Neither object is named by a `LoadObjectLayer` line in the 13 recovered
scenes. They are still preserved because both occur in the container table.
The JPEG name correspondence is useful for relinking; it does not establish
pixel equality with unavailable original TGA authoring files.

For manual reopening, use `demo-assets/prune_flower/C/PRUNE_Flower/` as the
LightWave content directory. Relink the historical drive paths and `.tga`
references to the recovered JPEGs in an editing copy. The preservation files
retain their exact original bytes.

## Limits

This validates extraction and file structure. It does not establish rendered
or timing parity with the original demo, plugin availability in a modern
LightWave installation, or the complete semantics of every object chunk.
The standalone MP3 is hash-verified against the ZIP; audio playback was not
part of this extraction. The UPX-unpacked demo executable was statically
inspected and was not run.

Reproduce the checks with:

```powershell
ctest --test-dir build -C Release --output-on-failure
```

Python 3.10+ is required. The full JPEG test uses Pillow and explicitly skips
if it is unavailable; it was installed and the test ran during preservation.

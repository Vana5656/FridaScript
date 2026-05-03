# FridaScript

Frida scripts for Android reverse-engineering research.

## `dex_dump.js`

DEX dumper that targets packers which zero/shift the DEX header and decrypt
classes lazily (DexProtector / Licel and similar).

### What it does

- Hooks the runtime so a DEX is captured the moment it is created or used:
  - `art::ClassLinker::DefineClass` (probes multiple `DexFile` layouts)
  - Multiple `DexFile` loaders (`OpenCommon`, `OpenMemory`, `OpenAndReadMagic`,
    `DexFileLoader::Open`, `ArtDexFileLoader::Open`)
  - `mmap` / `mmap64` — newly mapped pages with DEX magic
  - `mprotect` with `PROT_EXEC` — freshly decrypted code windows
  - `madvise(MADV_DONTNEED|MADV_FREE|MADV_REMOVE)` — rescue dump before wipe
  - `do_dlopen` — re-scan after packer libs land
- Repairs dumps that protectors break:
  - Zero/garbage header → searches the first 1 MiB for the real
    `dex\n035..040\0` signature, slices from that offset
  - Recomputes `file_size` (offset `0x20`)
  - Recomputes `signature` SHA-1 (offset `0x0C`, 20 bytes)
  - Recomputes `checksum` Adler-32 (offset `0x08`, 4 bytes LE)
  - Result passes strict DEX verifiers (jadx, baksmali, dex2jar, dexlib2)
- Region content watcher: same memory base re-dumped when contents change
  (catches lazy-decrypted methods landing in the same buffer)
- Dedup by SHA-1 of the final buffer (no duplicate files)
- Filenames include source, monotonic timestamp, and content hash:
  `classes_<NNN>_<source>_<t####>_<sha1[:12]>.dex`

### Usage

```bash
# Spawn so hooks are in place before the packer initializes:
frida -U -f <package> -l dex_dump.js --no-pause
```

After the script reports `[i] Active.`, exercise the app's flows
(login, main screens, settings, every feature you care about).
DexProtector decrypts on demand — anything you never invoke will not be
dumped.

Output: `/data/data/<package>/classes_*.dex` and `*.cdex`.
For CDEX, convert offline with [`vdex_extractor`](https://github.com/anestisb/vdex_extractor).

### Realistic caveats

- Last-version DexProtector with per-method JIT decryption keeps decrypted
  bytes in memory for very short windows. The `mprotect`/`madvise` rescue
  hooks help, but you may still get DEX dumps with holes — finish-by-finish
  prodding the app is unavoidable.
- After dumping, repacking still requires removing signature checks
  (`PackageManager.getPackageInfo(..., GET_SIGNATURES)` etc.) which is
  out of scope of this script.
- This is for personal research / interop. Don't ship a repack.

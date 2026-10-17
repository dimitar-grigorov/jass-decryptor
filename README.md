# Jass Decryptor

Free decryptor for the **`.jass` ransomware**: files renamed to `<name>.jass`, a ransom note `LOCKED.txt`, a Tor chat with a "personal ID" and an offer to "decrypt two files for free" for about 400 EUR.

The encryption turned out to be weak. The first 20000 bytes of every file are XOR-ed with one fixed keystream. The rest of the file is left as it was. There is no per-file key, no appended footer and no change in size. With the keystream, every file comes back byte for byte.

> **The keystream in this repository is proven for one victim.** It is not known whether the attackers reuse it. If your files use another one, the tool notices and writes nothing; see [Another victim, another key](#another-victim-another-key).

## Quick start (Windows)

1. Download `JassDecryptor.exe` from the Releases page. Nothing to install; it needs .NET Framework 4, which every Windows since 8 ships with.
2. Run it, choose a folder or a single file, or drop either onto the window, and press **Възстанови** (Restore). The interface is in Bulgarian.
3. Every `<name>.jass` is restored next to itself as `<name>`. The `.jass` files are only read, never changed.

If a file with the target name already exists:

| Existing file | What happens |
|---|---|
| identical to the restored content | nothing is written ("already there") |
| different | the tool shows both sizes and asks: **keep both** (writes `<name> (recovered).<ext>`), **replace** (the old file is renamed to `<name> (old).<ext>`, never deleted) or **skip** |

Before it writes anything, the tool decrypts the head of a sample of files with clear signatures (ZIP, PDF, PNG, XML, Office, SQL Server, ...). If they do not decrypt to their signature, it stops: the key does not fit. After each file it checks the format: ZIP/Office/ODF CRC32 of the entries in the decrypted zone, PNG chunk CRCs, XML well-formedness, a 7-Zip test for RAR/7z when 7-Zip is installed (found through its registry entry or PATH; without it those archives are restored but marked unverified), and headers for the rest. A CSV report is written to `JassDecryptor-reports` next to the exe.

Command line: `JassDecryptor.exe /cli <folder or file> [/conflict:beside|replace|skip] [/force]`. Exit code 0 = clean, 1 = some files need a look, 2 = the key does not fit, 3 = the key cannot be loaded.

## Repository

| Path | What |
|---|---|
| `csharp/` | `JassDecryptor.cs`, a single-file WinForms app (C# 5). `build.cmd` compiles it with the `csc.exe` that ships with .NET Framework 4. |
| `python/jass_decryptor.py` | Reference implementation; output is byte-identical to the C# tool. `python jass_decryptor.py <file or folder> <output folder>` |
| `python/derive_keystream.py` | Rebuilds a keystream from original/encrypted pairs. |
| `python/selftest.py` | Round-trip test: makes sample files, encrypts them with the keystream and checks that both tools restore them byte for byte. |
| `.github/workflows/build.yml` | Builds the exe and runs the round-trip test on every push; a `v*` tag publishes `JassDecryptor.exe` and its SHA-256 as a release. |
| `keystream/jass_keystream_20000.bin` | The keystream, SHA-256 `ffff0997f3ac60f55261adda046f2b264c6d2619bacca767d1e4b3a1c3d1cb3d`. |
| `samples/zero-filled.config.jass` | A genuine encrypted file whose original was 1241 zero bytes, so its content is the first 1241 bytes of the keystream. It holds no victim data. |

## Another victim, another key

1. Find one file whose original you still have, byte for byte the same version: a program file, a PDF from an e-mail, a template, a backup. **Original of 20000 bytes or more** gives the whole key at once; smaller ones only give their own length.
2. `python python/derive_keystream.py jass_keystream_20000.bin <original> <original>.jass`
3. Put `jass_keystream_20000.bin` next to `JassDecryptor.exe`. The window then shows "ключ: jass_keystream_20000.bin" instead of "вграден" (embedded).
4. Test on a copy of a ZIP, DOCX/XLSX or PNG first: their checksums prove the key.

An older copy of a file is not an original: wherever its content changed, the derived key is wrong. That is exactly the trap described in the case study below.

If this does not work for you, open an issue. Attach one non-sensitive original/encrypted pair if you can. Do not upload anything confidential.

## Case study

**The incident.** A small company found its files renamed to `*.jass` and a `LOCKED.txt` note. The most important file was a SQL Server 2008 R2 database: its backup existed only as an encrypted ZIP. The owner asked for that one file; everything else could be reinstalled.

**1. What the files say.** The end of the encrypted ZIP (its central directory) was readable, and once decrypted the archive validated at exactly its encrypted size. So only the head was touched and nothing was appended: no key or file ID is stored in the files.

**2. Plain copies.** Some application files existed both encrypted and unencrypted (older copies). XOR of a plain/encrypted pair was non-zero up to offset 19999 and zero after it, as long as the two versions did not differ. The XOR pattern was the same for different files. Conclusion: one keystream, 20000 bytes, applied from offset 0 of every file.

**3. The trap.** The first keystream came from the largest pair, a 1.2 MB Access database. It was wrong in 6 positions: the "plain" copy was an older version, and those 6 bytes had changed in the meantime. The decrypted ZIP failed its CRC.

**4. Proof.** The 6 positions were found by voting across many encrypted text files and by decompressing the ZIP's deflate stream. The final keystream is proven exact on all 20000 positions:
- the 11 MB ZIP decrypts and passes `zipfile.testzip()`: CRC32 of a 60 MB entry whose compressed data spans offsets 43 to 19999;
- a 43 MB RAR archive decrypts and passes `7z t` (5688 files);
- the database restores, and `DBCC CHECKDB WITH DATA_PURITY` reports no errors.

**5. Recovery.** 782 files were restored; all pass their format check except one whose original was all zeros. The database was back online the same day.

**Lessons.**
- Ransomware that encrypts only the head with a reused XOR keystream can be undone completely from one good original/encrypted pair.
- An "original" must be the exact same version. Check that the bytes after the encrypted zone are identical.
- Prove the key on something with checksums (ZIP, PNG, RAR, database pages), not on how the output "looks".

## Indicators

- Extension: `.jass` appended to the full file name (`report.pdf` becomes `report.pdf.jass`).
- Ransom note `LOCKED.txt`:
  ```
  YOUR COMPUTER WAS HACKED
  ALL OF YOUR FILES ARE ENCRYPTED WITH UNIQUE AND VERY STRONG PASSWORD
  Download and install Tor browser and navigate to http://slkbkfxzsh43wgmnm4t6gtiewrzojxoo2xmu4vdpsu2cdfzgyq76saqd.onion/
  we will decrypt two files for free
  price for the decryption tool and the password usually is around 400eur
  ```
- Encryption: XOR of bytes 0 to 19999 with a fixed keystream; file size unchanged; no marker or footer.
- Sample believed to be the encryptor, taken from the antivirus quarantine of the hit machine (not run, not analysed here):
  - `laweFc.exe`, 704512 bytes
  - SHA-256 `114def510f10ad21fd43534d635f518d0ed55ff0faf32e3297ba173d3ebb665d`
  - SHA-1 `7d664560b7d11d2c0d36b0ed40aafb55f47224bc`
  - MD5 `74bef176a795d8b39dfc32e4022a01c1`
  - VirusTotal (submitted inside `laweFc.zip`, SHA-256 `8aa92d6342d5d2b9010e719ec8f90e66a8c381bceca92bca15284b88d6a42a49`): <https://www.virustotal.com/gui/file/8aa92d6342d5d2b9010e719ec8f90e66a8c381bceca92bca15284b88d6a42a49>
- Family: not identified. In October 2026 No More Ransom listed no decryptor for `.jass`, and web searches found none. Builder kits such as Xorist let the operator choose the extension, note name and an XOR mode; that this is one of them is a guess, not a finding. The binary has not been analysed yet.

## Safety

- Work on copies when you can. The tool never changes `.jass` files, but disks of a hit machine deserve care.
- Do not pay before you have tried this; do not run "decryptors" from unknown sources.
- Change all passwords and close remote access (RDP) on the hit machine; the attackers most likely got in that way or a similar one.

## License

MIT, see [LICENSE](LICENSE). Copyright (c) 2026 Dimitar Grigorov.

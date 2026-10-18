# Changelog

## 1.1.2 (2026-10-18)

- The exe shows its real version in Properties (it said 1.0.0.0); releases take it from the tag.

## 1.1.1 (2026-10-18)

- The folder button opens the modern Windows folder picker.
- The path can be typed or pasted; Enter looks for `.jass` files there, a path that does not exist is shown in red.
- Restore is bold and gets the focus once files are found, so Enter starts it.
- A wait cursor while a dialog opens and while the key is checked.
- Releases carry a build attestation: `gh attestation verify JassDecryptor.exe -R dimitar-grigorov/jass-decryptor`.

## 1.1.0 (2026-10-17)

- Command line mode, polished: `/?` prints help, one line per file, a summary at the end, Ctrl+C stops after the current file.
- Bad options and folders without `.jass` files give a clear message and exit code 4.
- Output can be redirected to a file. Started without a console (Run dialog, shortcut), it opens its own.
- Two runs in the same second no longer overwrite each other's report.

## 1.0.1 (2026-10-17)

- The interface is in English.

## 1.0.0 (2026-10-17)

- First release: restores `.jass` files next to themselves, checks the key before writing and the format of every restored file, asks before touching an existing file.

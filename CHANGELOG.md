# Changelog

## 1.1.0 (2026-10-17)

- Command line mode, polished: `/?` prints help, one line per file, a summary at the end, Ctrl+C stops after the current file.
- Bad options and folders without `.jass` files give a clear message and exit code 4.
- Output can be redirected to a file. Started without a console (Run dialog, shortcut), it opens its own.
- Two runs in the same second no longer overwrite each other's report.

## 1.0.1 (2026-10-17)

- The interface is in English.

## 1.0.0 (2026-10-17)

- First release: restores `.jass` files next to themselves, checks the key before writing and the format of every restored file, asks before touching an existing file.

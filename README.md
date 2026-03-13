# NeoXtractor IDX

A PySide6 desktop tool for browsing, previewing, extracting, and viewing files from NeoX **SKPW IDX + WPK** archives.

This build is intentionally focused on the newer archive layout:

- input archive: `*.idx`
- data shards: `*.wpk`
- stage-1 payload handling: `CA / CP / CX`
- optional wrapped `ENONNXS3 -> NXS3`
- final preview/extract pipeline reuses the original GUI, image viewers, and mesh tooling

## What changed

- old `NXPK / EXPK (.npk)` support was removed from the archive reader
- the GUI now opens `*.idx`
- the backend reads matching `stem{pkg_id}.wpk` files automatically
- archive entries are exposed to the rest of the app through the same archive entry API so existing viewers continue to work

## Notes

- file names default to the 16-byte hash from the IDX table
- config-based renaming still works through the existing signature-to-name mapping
- image preview, text preview, and mesh viewers are kept from the original project

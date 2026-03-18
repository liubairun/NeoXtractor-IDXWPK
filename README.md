# NeoXtractor-IDXWPK

![Python versions](https://img.shields.io/badge/python-3.13.3-blue)


NeoXtractor-IDXWPK is a modified fork of NeoXtractor with extended support for NeoX and NeoX3 archive unpacking workflows.

This fork adds practical support for `IDX/WPK`, `slot_file`, and related nested payload decoding, in addition to the original `NPK/EXPK` archive workflow.

## Features

- Support for `NPK`, `EXPK`, `IDX`, and `WPK`
- Support for paired `WPK` packages and `slot_file` resources
- Nested payload decoding support for newer NeoX3 resource packages
- GUI-based archive browsing, preview, and extraction
- File renaming and config-based archive handling

## Usage

Run the GUI:

```bash
python main.py gui
```

If built as an executable:

```bash
NeoXtractor-IDXWPK.exe
```

## Status

This project is an actively modified fork focused on broader NeoX archive support, especially newer NeoX3 resource package unpacking.

Some archive variants and decoding paths are still sample-dependent.

## Thanks

This project is based on the original **NeoXtractor** by **MarcosVLl2** and contributors.

Many thanks to the original author for open-sourcing the foundation of this tool.

## Disclaimer

NeoX is an in-house game engine developed by NetEase.

This project is a modified fork of the original **NeoXtractor** and is **not affiliated with NetEase**.

For educational and research purposes only.

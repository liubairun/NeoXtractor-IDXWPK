Place custom format processors in this folder.

Supported plugin shapes:

1) Expose probe(data: bytes, entry) and decode(data: bytes, entry)
   decode may return either:
   - core.formats.base.FormatDecodeResult
   - dict with keys: data, extension, is_text, processor_name, metadata

Minimal example:

NAME = "MyFormat"
PRIORITY = 100


def probe(data, entry):
    return data[:4] == b"TEST"


def decode(data, entry):
    text = "decoded text here"
    return {
        "data": text,
        "extension": "txt",
        "is_text": True,
        "metadata": {"note": "custom plugin"},
    }

2) Expose PROCESSOR = <FormatProcessor instance>
   or get_processor() -> FormatProcessor

Built-in processors run first when they have a lower PRIORITY value.
You can also point the loader at another directory with:

    NEOXTRACTOR_PLUGIN_DIR=/path/to/plugins

"""Fixed byte transformations for operator-led evidence derivation."""

import base64
import zlib

FORMATS = ("slice", "base64", "gzip", "zlib")
INPUT_CAP = 32 * 1024 * 1024
OUTPUT_CAP = 64 * 1024 * 1024


def decode(method, data):
    if method not in FORMATS or len(data) > INPUT_CAP:
        raise ValueError("invalid_decode_request")
    if method == "slice":
        return data
    if method == "base64":
        return base64.b64decode(b"".join(data.split()), validate=True)

    wbits = 31 if method == "gzip" else 15
    parser = zlib.decompressobj(wbits)
    output = parser.decompress(data, OUTPUT_CAP + 1)
    if len(output) > OUTPUT_CAP or parser.unconsumed_tail:
        raise ValueError("decode_output_too_large")
    if not parser.eof or parser.unused_data:
        raise ValueError("incomplete_or_multiple_compressed_streams")
    return output

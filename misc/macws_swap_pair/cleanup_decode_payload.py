"""Bounded decode-only Python stdin payload builder; no native transport.

The default payload branch executes no bootstrap source and decodes no frame.
Explicit --decode hashes both independently pinned bootstrap sources before
executing either bootstrap. Those two library execs are distinct from framed
source execution, which is absent. All entries remain immutable source/data.
This payload has no cleanup flag, archive acknowledgement, gate, or factory.
"""

import base64
import hashlib
import json
import re

from macws_swap_pair import cleanup_package as package


CODEC_SHA256 = "b16a575a1cb57dd977c72078749eb5dcbbb165576e6e6ff275a63c5f7e45a5b0"
MAX_BOOTSTRAP_BYTES = 32 * 1024
MAX_FRAME_BYTES = 128 * 1024
R3_STDIN_MAX_BYTES = 256 * 1024


def _pinned(raw, digest, limit):
    package.need(type(raw) is bytes and 0 < len(raw) <= limit, "bounded_immutable_payload_input")
    package.need(type(digest) is str and re.fullmatch(r"[0-9a-f]{64}", digest, re.ASCII) is not None,
                 "independent_payload_sha256")
    package.need(hashlib.sha256(raw).hexdigest() == digest, "independent_payload_pin")


def build(*, frame_raw, trusted_frame_sha256, codec_source_raw, trusted_codec_sha256,
          package_source_raw, trusted_package_sha256, trusted_source_sha256, trusted_data_sha256):
    """Build stdin bytes only; caller pins are external, never selected by frame."""
    package.need(trusted_codec_sha256 == CODEC_SHA256, "unchanged_retained_frame_pin")
    _pinned(frame_raw, trusted_frame_sha256, MAX_FRAME_BYTES)
    _pinned(codec_source_raw, trusted_codec_sha256, MAX_BOOTSTRAP_BYTES)
    _pinned(package_source_raw, trusted_package_sha256, MAX_BOOTSTRAP_BYTES)
    source_pins = package._pins(trusted_source_sha256, package.SOURCE_NAMES)
    data_pins = package._pins(trusted_data_sha256, package.DATA_NAMES)
    literals = {
        "codec_b64": base64.b64encode(codec_source_raw).decode("ascii"),
        "codec_sha256": trusted_codec_sha256,
        "package_b64": base64.b64encode(package_source_raw).decode("ascii"),
        "package_sha256": trusted_package_sha256,
        "frame_b64": base64.b64encode(frame_raw).decode("ascii"),
        "frame_sha256": trusted_frame_sha256,
        "source_pins": source_pins, "data_pins": data_pins,
    }
    # repr, not shell interpolation. All binary data is ASCII base64 literal.
    prefix = "# Private build-only cleanup package; no native action.\n"
    prefix += "import base64, hashlib, json, sys\n"
    prefix += "DEFAULT = " + repr(package.metadata()) + "\n"
    prefix += "FROZEN = " + repr(literals) + "\n"
    body = '''
def refused():
    raise ValueError("decode_only_payload_refused")

def checked_b64(word, limit):
    if type(word) is not str or len(word) > 4 * ((limit + 2) // 3): refused()
    try: raw = base64.b64decode(word.encode("ascii"), validate=True)
    except (ValueError, UnicodeError): refused()
    if not 0 < len(raw) <= limit: refused()
    return raw

def decode_only():
    # Both exact bootstrap byte pins and frame integrity are checked before
    # the first bootstrap exec. The frame hash itself grants no authority.
    codec_raw = checked_b64(FROZEN["codec_b64"], 32768)
    package_raw = checked_b64(FROZEN["package_b64"], 32768)
    frame_raw = checked_b64(FROZEN["frame_b64"], 131072)
    for raw, name in ((codec_raw, "codec"), (package_raw, "package"), (frame_raw, "frame")):
        if hashlib.sha256(raw).hexdigest() != FROZEN[name + "_sha256"]: refused()
    codec = {"__name__": "macws_pinned_retained_frame"}
    module = {"__name__": "macws_pinned_cleanup_package"}
    # No framed source is compiled, exec'd, imported, or instantiated.
    exec(compile(codec_raw, "retained_frame.pinned.py", "exec"), codec)
    exec(compile(package_raw, "cleanup_package.pinned.py", "exec"), module)
    class Codec:
        decode = staticmethod(codec["decode"])
    verified = module["decode"](frame_raw=frame_raw,
        trusted_source_sha256=FROZEN["source_pins"], trusted_data_sha256=FROZEN["data_pins"], codec=Codec)
    print(json.dumps(verified.summary(), sort_keys=True))

if sys.argv[1:] == []:
    print(json.dumps(DEFAULT, sort_keys=True))
elif sys.argv[1:] == ["--decode"]:
    decode_only()
else:
    refused()
'''
    result = (prefix + body).encode("ascii")
    package.need(len(result) <= R3_STDIN_MAX_BYTES, "unchanged_r3_stdin_budget")
    return result


def metadata():
    return {"schema": "macws.current-installation-cleanup.decode-payload.v1",
            "default_inert": True, "payload_build_only": True,
            "native_transport": False, "framed_source_execution": False,
            "max_stdin_bytes": R3_STDIN_MAX_BYTES, "device_acceptance": False}


if __name__ == "__main__":
    print(json.dumps(metadata(), sort_keys=True))

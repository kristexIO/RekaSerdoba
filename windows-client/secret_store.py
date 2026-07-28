import ctypes
import json
import os
from ctypes import wintypes
from pathlib import Path


class DataBlob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]


def _blob(value):
    buffer = ctypes.create_string_buffer(value)
    return DataBlob(len(value), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_byte))), buffer


def protect(value):
    if os.name != "nt":
        raise OSError("DPAPI is available only on Windows")
    source, source_buffer = _blob(value)
    entropy, entropy_buffer = _blob(b"RekaSerdoba/1 device bundle")
    output = DataBlob()
    if not ctypes.windll.crypt32.CryptProtectData(
        ctypes.byref(source),
        "RekaSerdoba device",
        ctypes.byref(entropy),
        None,
        None,
        0x05,
        ctypes.byref(output),
    ):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(output.pbData, output.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(output.pbData)
        del source_buffer, entropy_buffer


def unprotect(value):
    if os.name != "nt":
        raise OSError("DPAPI is available only on Windows")
    source, source_buffer = _blob(value)
    entropy, entropy_buffer = _blob(b"RekaSerdoba/1 device bundle")
    output = DataBlob()
    description = wintypes.LPWSTR()
    if not ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(source),
        ctypes.byref(description),
        ctypes.byref(entropy),
        None,
        None,
        0x01,
        ctypes.byref(output),
    ):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(output.pbData, output.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(output.pbData)
        if description:
            ctypes.windll.kernel32.LocalFree(description)
        del source_buffer, entropy_buffer


def import_bundle(source, target):
    value = json.loads(Path(source).read_text(encoding="utf-8"))
    required = {
        "client_id_b64",
        "client_signing_seed_b64",
        "gate_key_b64",
        "manifest_signing_public_key_b64",
        "manifest_url",
    }
    if not required.issubset(value):
        raise ValueError("device bundle is incomplete")
    target = Path(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(".new")
    temporary.write_bytes(protect(json.dumps(value, separators=(",", ":")).encode()))
    os.replace(temporary, target)
    if os.name == "nt" and os.environ.get("REKASERDOBA_DEV_ACL") != "1":
        import subprocess

        subprocess.run(
            [
                "icacls.exe",
                str(target.parent),
                "/inheritance:r",
                "/grant:r",
                "*S-1-5-18:(OI)(CI)F",
                "*S-1-5-32-544:(OI)(CI)F",
            ],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                "icacls.exe",
                str(target),
                "/inheritance:r",
                "/grant:r",
                "*S-1-5-18:F",
                "*S-1-5-32-544:F",
            ],
            check=True,
            capture_output=True,
        )


def load_bundle(path):
    return json.loads(unprotect(Path(path).read_bytes()).decode())

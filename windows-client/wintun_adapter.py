import ctypes
import ipaddress
import os
import subprocess
import uuid
from ctypes import wintypes
from pathlib import Path


class Guid(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    ]


def guid(value):
    parsed = uuid.UUID(value)
    encoded = parsed.bytes_le
    return Guid.from_buffer_copy(encoded)


class WintunAdapter:
    def __init__(self, dll_path, name="RekaSerdoba"):
        if os.name != "nt":
            raise OSError("Wintun is available only on Windows")
        self.dll = ctypes.WinDLL(str(Path(dll_path).resolve()), use_last_error=True)
        self._configure_api()
        requested = guid("7d1a2e5d-cd36-47d9-9931-274921ae4f41")
        self.adapter = self.dll.WintunCreateAdapter(name, "RekaSerdoba", ctypes.byref(requested))
        if not self.adapter:
            raise ctypes.WinError()
        self.session = self.dll.WintunStartSession(self.adapter, 0x400000)
        if not self.session:
            self.dll.WintunCloseAdapter(self.adapter)
            raise ctypes.WinError()
        self.event = self.dll.WintunGetReadWaitEvent(self.session)
        self.name = name

    def _configure_api(self):
        self.dll.WintunCreateAdapter.argtypes = [
            wintypes.LPCWSTR,
            wintypes.LPCWSTR,
            ctypes.POINTER(Guid),
        ]
        self.dll.WintunCreateAdapter.restype = wintypes.HANDLE
        self.dll.WintunCloseAdapter.argtypes = [wintypes.HANDLE]
        self.dll.WintunStartSession.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        self.dll.WintunStartSession.restype = wintypes.HANDLE
        self.dll.WintunEndSession.argtypes = [wintypes.HANDLE]
        self.dll.WintunGetReadWaitEvent.argtypes = [wintypes.HANDLE]
        self.dll.WintunGetReadWaitEvent.restype = wintypes.HANDLE
        self.dll.WintunReceivePacket.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        self.dll.WintunReceivePacket.restype = ctypes.POINTER(ctypes.c_ubyte)
        self.dll.WintunReleaseReceivePacket.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(ctypes.c_ubyte),
        ]
        self.dll.WintunAllocateSendPacket.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        self.dll.WintunAllocateSendPacket.restype = ctypes.POINTER(ctypes.c_ubyte)
        self.dll.WintunSendPacket.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(ctypes.c_ubyte),
        ]

    def configure(self, address, prefix, mtu):
        mask = str(ipaddress.ip_network(f"0.0.0.0/{prefix}").netmask)
        _run(
            "netsh",
            "interface",
            "ipv4",
            "set",
            "address",
            f"name={self.name}",
            "source=static",
            f"address={address}",
            f"mask={mask}",
            "gateway=none",
        )
        _run(
            "netsh",
            "interface",
            "ipv4",
            "set",
            "subinterface",
            self.name,
            f"mtu={mtu}",
            "store=active",
        )

    def receive(self, timeout_ms=500):
        size = wintypes.DWORD()
        packet = self.dll.WintunReceivePacket(self.session, ctypes.byref(size))
        if packet:
            try:
                return ctypes.string_at(packet, size.value)
            finally:
                self.dll.WintunReleaseReceivePacket(self.session, packet)
        error = ctypes.get_last_error()
        if error != 259:
            raise ctypes.WinError(error)
        result = ctypes.windll.kernel32.WaitForSingleObject(self.event, timeout_ms)
        if result in (0x102, 0):
            return None
        raise ctypes.WinError()

    def send(self, value):
        packet = self.dll.WintunAllocateSendPacket(self.session, len(value))
        if not packet:
            raise ctypes.WinError()
        ctypes.memmove(packet, value, len(value))
        self.dll.WintunSendPacket(self.session, packet)

    def close(self):
        if self.session:
            self.dll.WintunEndSession(self.session)
            self.session = None
        if self.adapter:
            self.dll.WintunCloseAdapter(self.adapter)
            self.adapter = None


def _run(*args):
    subprocess.run(args, check=True, capture_output=True, text=True)

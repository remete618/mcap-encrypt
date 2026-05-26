"""Binary read/write helpers for MCAP and mcap-encrypt records.

All integers are little-endian. Strings are uint32-length-prefixed UTF-8.
Byte fields are uint32-length-prefixed raw bytes.
"""
from __future__ import annotations

import struct


class BinaryReader:
    """Wrap a bytes-like object and read fields sequentially."""

    __slots__ = ("_data", "_pos")

    def __init__(self, data: bytes | bytearray | memoryview) -> None:
        self._data = memoryview(data) if not isinstance(data, memoryview) else data
        self._pos = 0

    @property
    def pos(self) -> int:
        return self._pos

    @property
    def remaining(self) -> int:
        return len(self._data) - self._pos

    def read_exact(self, n: int) -> memoryview:
        if self._pos + n > len(self._data):
            raise ValueError(
                f"truncated: need {n} bytes at offset {self._pos}, "
                f"only {len(self._data) - self._pos} remain"
            )
        view = self._data[self._pos : self._pos + n]
        self._pos += n
        return view

    def read_u8(self) -> int:
        return struct.unpack_from("<B", self.read_exact(1))[0]

    def read_u16(self) -> int:
        return struct.unpack_from("<H", self.read_exact(2))[0]

    def read_u32(self) -> int:
        return struct.unpack_from("<I", self.read_exact(4))[0]

    def read_u64(self) -> int:
        return struct.unpack_from("<Q", self.read_exact(8))[0]

    def read_prefixed_bytes(self) -> bytes:
        """Read uint32-length-prefixed bytes field."""
        length = self.read_u32()
        return bytes(self.read_exact(length))

    def read_string(self) -> str:
        """Read uint32-length-prefixed UTF-8 string."""
        raw = self.read_prefixed_bytes()
        return raw.decode("utf-8")

    def read_map(self) -> dict[str, str]:
        """Read uint32-count-prefixed map of string->string pairs."""
        count = self.read_u32()
        result: dict[str, str] = {}
        for _ in range(count):
            k = self.read_string()
            v = self.read_string()
            result[k] = v
        return result

    def is_eof(self) -> bool:
        return self._pos >= len(self._data)


class BinaryWriter:
    """Append binary fields into a bytearray."""

    __slots__ = ("_buf",)

    def __init__(self) -> None:
        self._buf = bytearray()

    def write_u8(self, v: int) -> None:
        self._buf += struct.pack("<B", v)

    def write_u16(self, v: int) -> None:
        self._buf += struct.pack("<H", v)

    def write_u32(self, v: int) -> None:
        self._buf += struct.pack("<I", v)

    def write_u64(self, v: int) -> None:
        self._buf += struct.pack("<Q", v)

    def write_prefixed_bytes(self, data: bytes | bytearray) -> None:
        """Write uint32-length-prefixed bytes field."""
        self.write_u32(len(data))
        self._buf += data

    def write_string(self, s: str) -> None:
        """Write uint32-length-prefixed UTF-8 string."""
        self.write_prefixed_bytes(s.encode("utf-8"))

    def write_map(self, m: dict[str, str]) -> None:
        """Write uint32-count-prefixed map of string->string pairs."""
        self.write_u32(len(m))
        for k, v in m.items():
            self.write_string(k)
            self.write_string(v)

    def write_raw(self, data: bytes | bytearray) -> None:
        self._buf += data

    def get_bytes(self) -> bytes:
        return bytes(self._buf)

    def __len__(self) -> int:
        return len(self._buf)

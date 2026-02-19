"""
Microsoft Bond CompactBinaryV1 Protocol - Serializer/Deserializer

Implementation based on the Microsoft Bond open-source specification.
https://github.com/microsoft/bond

This implements the CompactBinaryV1 wire protocol format used by
Windows Defender's MAPS (Microsoft Active Protection Service) for
cloud-based file reputation queries.

Wire Format Summary (Defender variant of CompactBinaryV1):
  Field header: 1 byte
    - Bits [0:4] (5 bits) = BondDataType
    - Bits [5:7] (3 bits) = field ordinal delta
    - If delta 1-5: field_id = previous_field_id + delta
    - If delta == 6: followed by uint8 absolute field ordinal (0-255)
    - If delta == 7: followed by uint16 LE absolute field ordinal (0-65535)
  Values: type-specific encoding (varints, zigzag, length-prefixed, etc.)
  Structs: sequence of fields terminated by BT_STOP (0x00)
  BT_STOP_BASE (0x01) terminates a base class level and resets field counter.

  Bonded<T> envelope (wraps all MAPS payloads):
    CB marshal header: 43 42 01 00 (4 bytes)
    Outer struct:
      F5 STRING = schema name
      BT_STOP_BASE x2
      F10 LIST<LIST<INT8>> = [[]]  (empty runtime type info)
      F20 STRUCT:
        F5 STRING = schema name
        BT_STOP_BASE x2
        [payload fields...]
      BT_STOP
    BT_STOP
"""

import struct
from enum import IntEnum
from io import BytesIO
from typing import Any, Dict, List, Optional, Tuple, Union


# ---------------------------------------------------------------------------
# Bond data types
# ---------------------------------------------------------------------------

class BondType(IntEnum):
    BT_STOP      = 0
    BT_STOP_BASE = 1
    BT_BOOL      = 2
    BT_UINT8     = 3
    BT_UINT16    = 4
    BT_UINT32    = 5
    BT_UINT64    = 6
    BT_FLOAT     = 7
    BT_DOUBLE    = 8
    BT_STRING    = 9
    BT_STRUCT    = 10
    BT_LIST      = 11
    BT_SET       = 12
    BT_MAP       = 13
    BT_INT8      = 14
    BT_INT16     = 15
    BT_INT32     = 16
    BT_INT64     = 17
    BT_WSTRING   = 18


BOND_TYPE_NAMES = {v: v.name for v in BondType}


# ---------------------------------------------------------------------------
# Varint / ZigZag helpers
# ---------------------------------------------------------------------------

def encode_varint(value: int) -> bytes:
    """Encode an unsigned integer as a variable-length integer."""
    if value < 0:
        raise ValueError(f"encode_varint requires unsigned value, got {value}")
    buf = bytearray()
    while value > 0x7F:
        buf.append((value & 0x7F) | 0x80)
        value >>= 7
    buf.append(value & 0x7F)
    return bytes(buf)


def decode_varint(stream: BytesIO) -> int:
    """Decode a variable-length integer from a byte stream."""
    result = 0
    shift = 0
    while True:
        raw = stream.read(1)
        if not raw:
            raise EOFError("Unexpected end of stream reading varint")
        b = raw[0]
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
        if shift > 63:
            raise ValueError("Varint too large")
    return result


def zigzag_encode(value: int) -> int:
    """ZigZag-encode a signed integer to unsigned."""
    if value >= 0:
        return value << 1
    return ((-value) << 1) - 1


def zigzag_decode(value: int) -> int:
    """ZigZag-decode an unsigned integer to signed."""
    if value & 1:
        return -(value >> 1) - 1
    return value >> 1


# ---------------------------------------------------------------------------
# CompactBinaryV1 Writer
# ---------------------------------------------------------------------------

class CompactBinaryV1Writer:
    """Serialize data into Bond CompactBinaryV1 wire format."""

    def __init__(self):
        self._buf = BytesIO()
        self._field_stack: List[int] = [0]  # previous field ID per nesting level

    # -- raw writers --------------------------------------------------------

    def _write(self, data: bytes):
        self._buf.write(data)

    def _write_byte(self, value: int):
        self._buf.write(bytes([value & 0xFF]))

    def _write_uint16_le(self, value: int):
        self._buf.write(struct.pack('<H', value))

    def _write_float_le(self, value: float):
        self._buf.write(struct.pack('<f', value))

    def _write_double_le(self, value: float):
        self._buf.write(struct.pack('<d', value))

    def _write_varint(self, value: int):
        self._write(encode_varint(value))

    # -- field headers ------------------------------------------------------

    def write_field_begin(self, bond_type: int, field_id: int):
        """Write a field header byte (and optional extended field ID).

        Encoding (Defender variant):
          delta 1-5: inline delta in header byte
          delta >= 6, ordinal <= 255: header with delta=6, uint8 absolute ordinal
          delta >= 6, ordinal > 255: header with delta=7, uint16 LE absolute ordinal
        """
        prev = self._field_stack[-1]
        delta = field_id - prev
        self._field_stack[-1] = field_id

        if 1 <= delta <= 5:
            self._write_byte((delta << 5) | (bond_type & 0x1F))
        elif field_id <= 255:
            # Extended uint8 ordinal (delta=6 in header)
            self._write_byte(0xC0 | (bond_type & 0x1F))
            self._write_byte(field_id)
        else:
            # Extended uint16 LE ordinal (delta=7 in header)
            self._write_byte(0xE0 | (bond_type & 0x1F))
            self._write_uint16_le(field_id)

    # -- struct boundaries --------------------------------------------------

    def write_struct_begin(self):
        """Push a new struct nesting level."""
        self._field_stack.append(0)

    def write_struct_end(self):
        """End current struct with BT_STOP."""
        self._write_byte(BondType.BT_STOP)
        self._field_stack.pop()

    def write_base_end(self):
        """End base struct with BT_STOP_BASE and pop nesting level."""
        self._write_byte(BondType.BT_STOP_BASE)
        self._field_stack.pop()

    def write_stop_base(self):
        """Write BT_STOP_BASE and reset field counter (no stack pop).

        Used for base class boundaries within the Bonded<T> envelope,
        where we stay at the same nesting level but reset field IDs.
        """
        self._write_byte(BondType.BT_STOP_BASE)
        self._field_stack[-1] = 0

    # -- typed field writers ------------------------------------------------

    def write_bool(self, field_id: int, value: bool):
        self.write_field_begin(BondType.BT_BOOL, field_id)
        self._write_byte(1 if value else 0)

    def write_uint8(self, field_id: int, value: int):
        self.write_field_begin(BondType.BT_UINT8, field_id)
        self._write_byte(value)

    def write_uint16(self, field_id: int, value: int):
        self.write_field_begin(BondType.BT_UINT16, field_id)
        self._write_varint(value)

    def write_uint32(self, field_id: int, value: int):
        self.write_field_begin(BondType.BT_UINT32, field_id)
        self._write_varint(value)

    def write_uint64(self, field_id: int, value: int):
        self.write_field_begin(BondType.BT_UINT64, field_id)
        self._write_varint(value)

    def write_int8(self, field_id: int, value: int):
        self.write_field_begin(BondType.BT_INT8, field_id)
        self._write_byte(zigzag_encode(value) & 0xFF)

    def write_int16(self, field_id: int, value: int):
        self.write_field_begin(BondType.BT_INT16, field_id)
        self._write_varint(zigzag_encode(value))

    def write_int32(self, field_id: int, value: int):
        self.write_field_begin(BondType.BT_INT32, field_id)
        self._write_varint(zigzag_encode(value))

    def write_int64(self, field_id: int, value: int):
        self.write_field_begin(BondType.BT_INT64, field_id)
        self._write_varint(zigzag_encode(value))

    def write_float(self, field_id: int, value: float):
        self.write_field_begin(BondType.BT_FLOAT, field_id)
        self._write_float_le(value)

    def write_double(self, field_id: int, value: float):
        self.write_field_begin(BondType.BT_DOUBLE, field_id)
        self._write_double_le(value)

    def write_string(self, field_id: int, value: str):
        self.write_field_begin(BondType.BT_STRING, field_id)
        encoded = value.encode('utf-8')
        self._write_varint(len(encoded))
        self._write(encoded)

    def write_wstring(self, field_id: int, value: str):
        self.write_field_begin(BondType.BT_WSTRING, field_id)
        self._write_varint(len(value))  # character count
        self._write(value.encode('utf-16-le'))

    def write_blob(self, field_id: int, data: bytes):
        """Write raw bytes as a list<uint8> (blob)."""
        self.write_field_begin(BondType.BT_LIST, field_id)
        self._write_byte(BondType.BT_UINT8)
        self._write_varint(len(data))
        self._write(data)

    # -- container writers --------------------------------------------------

    def write_list_begin(self, field_id: int, element_type: int, count: int):
        self.write_field_begin(BondType.BT_LIST, field_id)
        self._write_byte(element_type & 0xFF)
        self._write_varint(count)

    def write_set_begin(self, field_id: int, element_type: int, count: int):
        self.write_field_begin(BondType.BT_SET, field_id)
        self._write_byte(element_type & 0xFF)
        self._write_varint(count)

    def write_map_begin(self, field_id: int, key_type: int, value_type: int, count: int):
        self.write_field_begin(BondType.BT_MAP, field_id)
        self._write_byte(key_type & 0xFF)
        self._write_byte(value_type & 0xFF)
        self._write_varint(count)

    # -- container element writers (no field header) ------------------------

    def write_container_bool(self, value: bool):
        self._write_byte(1 if value else 0)

    def write_container_uint8(self, value: int):
        self._write_byte(value)

    def write_container_uint16(self, value: int):
        self._write_varint(value)

    def write_container_uint32(self, value: int):
        self._write_varint(value)

    def write_container_uint64(self, value: int):
        self._write_varint(value)

    def write_container_int8(self, value: int):
        self._write_byte(zigzag_encode(value) & 0xFF)

    def write_container_int16(self, value: int):
        self._write_varint(zigzag_encode(value))

    def write_container_int32(self, value: int):
        self._write_varint(zigzag_encode(value))

    def write_container_int64(self, value: int):
        self._write_varint(zigzag_encode(value))

    def write_container_float(self, value: float):
        self._write_float_le(value)

    def write_container_double(self, value: float):
        self._write_double_le(value)

    def write_container_string(self, value: str):
        encoded = value.encode('utf-8')
        self._write_varint(len(encoded))
        self._write(encoded)

    def write_container_wstring(self, value: str):
        self._write_varint(len(value))
        self._write(value.encode('utf-16-le'))

    def write_container_struct_begin(self):
        self._field_stack.append(0)

    def write_container_struct_end(self):
        self.write_struct_end()

    # -- output -------------------------------------------------------------

    def get_data(self) -> bytes:
        """Return the serialized byte buffer."""
        return self._buf.getvalue()

    def __len__(self) -> int:
        return self._buf.tell()

    def reset(self):
        self._buf = BytesIO()
        self._field_stack = [0]


# ---------------------------------------------------------------------------
# CompactBinaryV1 Reader
# ---------------------------------------------------------------------------

class CompactBinaryV1Reader:
    """Deserialize data from Bond CompactBinaryV1 wire format."""

    def __init__(self, data: bytes):
        self._stream = BytesIO(data)
        self._field_stack: List[int] = [0]

    # -- raw readers --------------------------------------------------------

    def _read(self, n: int) -> bytes:
        data = self._stream.read(n)
        if len(data) < n:
            raise EOFError(f"Expected {n} bytes at offset {self._stream.tell()}, got {len(data)}")
        return data

    def _read_byte(self) -> int:
        return self._read(1)[0]

    def _read_uint16_le(self) -> int:
        return struct.unpack('<H', self._read(2))[0]

    def _read_uint32_le(self) -> int:
        return struct.unpack('<I', self._read(4))[0]

    def _read_uint64_le(self) -> int:
        return struct.unpack('<Q', self._read(8))[0]

    def _read_float_le(self) -> float:
        return struct.unpack('<f', self._read(4))[0]

    def _read_double_le(self) -> float:
        return struct.unpack('<d', self._read(8))[0]

    def _read_varint(self) -> int:
        return decode_varint(self._stream)

    # -- field header -------------------------------------------------------

    def read_field(self) -> Tuple[int, int]:
        """Read a field header. Returns (bond_type, field_id).

        Returns (BT_STOP, 0) or (BT_STOP_BASE, 0) at end of struct.

        Extended ordinal encoding (Defender variant):
          delta 1-5: field_id = previous + delta
          delta == 6: read uint8 absolute ordinal
          delta == 7: read uint16 LE absolute ordinal
        """
        raw = self._read_byte()
        bond_type = raw & 0x1F
        delta = raw >> 5

        if bond_type == BondType.BT_STOP:
            return BondType.BT_STOP, 0
        if bond_type == BondType.BT_STOP_BASE:
            self._field_stack[-1] = 0  # Reset field counter
            return BondType.BT_STOP_BASE, 0

        if delta < 6:
            self._field_stack[-1] += delta
        elif delta == 6:
            self._field_stack[-1] = self._read_byte()
        else:  # delta == 7
            self._field_stack[-1] = self._read_uint16_le()

        return bond_type, self._field_stack[-1]

    # -- struct boundaries --------------------------------------------------

    def read_struct_begin(self):
        self._field_stack.append(0)

    def read_struct_end(self):
        if self._field_stack:
            self._field_stack.pop()

    # -- typed value readers ------------------------------------------------

    def read_bool(self) -> bool:
        return self._read_byte() != 0

    def read_uint8(self) -> int:
        return self._read_byte()

    def read_uint16(self) -> int:
        return self._read_varint()

    def read_uint32(self) -> int:
        return self._read_varint()

    def read_uint64(self) -> int:
        return self._read_varint()

    def read_int8(self) -> int:
        return zigzag_decode(self._read_byte())

    def read_int16(self) -> int:
        return zigzag_decode(self._read_varint())

    def read_int32(self) -> int:
        return zigzag_decode(self._read_varint())

    def read_int64(self) -> int:
        return zigzag_decode(self._read_varint())

    def read_float(self) -> float:
        return self._read_float_le()

    def read_double(self) -> float:
        return self._read_double_le()

    def read_string(self) -> str:
        length = self._read_varint()
        return self._read(length).decode('utf-8', errors='replace')

    def read_wstring(self) -> str:
        char_count = self._read_varint()
        return self._read(char_count * 2).decode('utf-16-le', errors='replace')

    # -- container readers --------------------------------------------------

    def read_list_begin(self) -> Tuple[int, int]:
        """Returns (element_type, count)."""
        element_type = self._read_byte()
        count = self._read_varint()
        return element_type, count

    def read_set_begin(self) -> Tuple[int, int]:
        return self.read_list_begin()

    def read_map_begin(self) -> Tuple[int, int, int]:
        """Returns (key_type, value_type, count)."""
        key_type = self._read_byte()
        value_type = self._read_byte()
        count = self._read_varint()
        return key_type, value_type, count

    # -- generic value reader -----------------------------------------------

    def read_value(self, bond_type: int) -> Any:
        """Read a single value of the specified Bond type."""
        if bond_type == BondType.BT_BOOL:
            return self.read_bool()
        elif bond_type == BondType.BT_UINT8:
            return self.read_uint8()
        elif bond_type == BondType.BT_UINT16:
            return self.read_uint16()
        elif bond_type == BondType.BT_UINT32:
            return self.read_uint32()
        elif bond_type == BondType.BT_UINT64:
            return self.read_uint64()
        elif bond_type == BondType.BT_INT8:
            return self.read_int8()
        elif bond_type == BondType.BT_INT16:
            return self.read_int16()
        elif bond_type == BondType.BT_INT32:
            return self.read_int32()
        elif bond_type == BondType.BT_INT64:
            return self.read_int64()
        elif bond_type == BondType.BT_FLOAT:
            return self.read_float()
        elif bond_type == BondType.BT_DOUBLE:
            return self.read_double()
        elif bond_type == BondType.BT_STRING:
            return self.read_string()
        elif bond_type == BondType.BT_WSTRING:
            return self.read_wstring()
        elif bond_type == BondType.BT_STRUCT:
            return self.read_struct_generic()
        elif bond_type in (BondType.BT_LIST, BondType.BT_SET):
            elem_type, count = self.read_list_begin()
            # Optimise blob (list<uint8/int8>) to raw bytes.
            # INT8 in containers is stored as raw bytes (no zigzag),
            # confirmed from MAPS FASTPATH response wire analysis.
            if elem_type in (BondType.BT_UINT8, BondType.BT_INT8):
                return self._read(count)
            return [self.read_value(elem_type) for _ in range(count)]
        elif bond_type == BondType.BT_MAP:
            kt, vt, count = self.read_map_begin()
            return {self.read_value(kt): self.read_value(vt) for _ in range(count)}
        else:
            raise ValueError(f"Unknown Bond type {bond_type}")

    def read_struct_generic(self) -> Dict[int, Tuple[str, Any]]:
        """Read an entire struct without a schema.

        Returns dict mapping field_id -> (type_name, value).
        BT_STOP_BASE resets field counter but continues reading.
        BT_STOP terminates the struct.
        """
        self.read_struct_begin()
        fields: Dict[int, Tuple[str, Any]] = {}
        while True:
            bt, fid = self.read_field()
            if bt == BondType.BT_STOP:
                break
            if bt == BondType.BT_STOP_BASE:
                continue  # Field counter already reset in read_field
            type_name = BOND_TYPE_NAMES.get(bt, f"unknown({bt})")
            value = self.read_value(bt)
            fields[fid] = (type_name, value)
        self.read_struct_end()
        return fields

    # -- skip ---------------------------------------------------------------

    def skip_value(self, bond_type: int):
        """Skip over a value of the given type without returning it."""
        if bond_type == BondType.BT_BOOL:
            self._read_byte()
        elif bond_type == BondType.BT_UINT8:
            self._read_byte()
        elif bond_type in (BondType.BT_UINT16, BondType.BT_UINT32, BondType.BT_UINT64):
            self._read_varint()
        elif bond_type == BondType.BT_INT8:
            self._read_byte()
        elif bond_type in (BondType.BT_INT16, BondType.BT_INT32, BondType.BT_INT64):
            self._read_varint()
        elif bond_type == BondType.BT_FLOAT:
            self._read(4)
        elif bond_type == BondType.BT_DOUBLE:
            self._read(8)
        elif bond_type == BondType.BT_STRING:
            self._read(self._read_varint())
        elif bond_type == BondType.BT_WSTRING:
            self._read(self._read_varint() * 2)
        elif bond_type == BondType.BT_STRUCT:
            self._skip_struct()
        elif bond_type in (BondType.BT_LIST, BondType.BT_SET):
            et, count = self.read_list_begin()
            for _ in range(count):
                self.skip_value(et)
        elif bond_type == BondType.BT_MAP:
            kt, vt, count = self.read_map_begin()
            for _ in range(count):
                self.skip_value(kt)
                self.skip_value(vt)

    def _skip_struct(self):
        self.read_struct_begin()
        while True:
            bt, _ = self.read_field()
            if bt == BondType.BT_STOP:
                break
            if bt == BondType.BT_STOP_BASE:
                continue
            self.skip_value(bt)
        self.read_struct_end()

    # -- stream info --------------------------------------------------------

    @property
    def position(self) -> int:
        return self._stream.tell()

    @property
    def remaining(self) -> int:
        pos = self._stream.tell()
        self._stream.seek(0, 2)
        end = self._stream.tell()
        self._stream.seek(pos)
        return end - pos


# ---------------------------------------------------------------------------
# High-level helpers
# ---------------------------------------------------------------------------

def bond_serialize(fields: Dict[int, Tuple[int, Any]]) -> bytes:
    """Serialize a flat dict of {field_id: (bond_type, value)} to Bond binary.

    Supports nested structs via recursive dicts of the same shape.
    Returns raw struct bytes (no marshal header).
    """
    w = CompactBinaryV1Writer()
    _write_fields(w, fields)
    w._write_byte(BondType.BT_STOP)
    return w.get_data()


# Bond CompactBinary v1 protocol magic (ProtocolType.COMPACT_PROTOCOL = 0x4243)
BOND_COMPACT_PROTOCOL_MAGIC = 0x4243
BOND_COMPACT_V1_VERSION = 1
# Pre-computed 4-byte marshal header: magic (LE uint16) + version (LE uint16)
BOND_CB1_MARSHAL_HEADER = struct.pack('<HH', BOND_COMPACT_PROTOCOL_MAGIC, BOND_COMPACT_V1_VERSION)


def bond_marshal(fields: Dict[int, Tuple[int, Any]]) -> bytes:
    """Marshal a Bond struct with the standard 4-byte header.

    Bond Marshal format:
      - uint16 LE: protocol magic (0x4243 = 'CB' = COMPACT_PROTOCOL)
      - uint16 LE: version (1 for CompactBinary v1)
      - followed by the serialized struct data (fields + BT_STOP)
    """
    header = struct.pack('<HH', BOND_COMPACT_PROTOCOL_MAGIC, BOND_COMPACT_V1_VERSION)
    return header + bond_serialize(fields)


def bond_marshal_with_schema(
    schema_name: str,
    fields: Dict[int, Tuple[int, Any]],
) -> bytes:
    """Marshal a Bond struct wrapped in the Bonded<T> envelope.

    This produces the exact wire format used by Windows Defender MAPS:
      CB header (4 bytes)
      Outer struct:
        F5 STRING = schema_name
        BT_STOP_BASE x2
        F10 LIST<LIST<INT8>> = [[]]
        F20 STRUCT:
          F5 STRING = schema_name
          BT_STOP_BASE x2
          [payload fields...]
        BT_STOP
      BT_STOP
    """
    w = CompactBinaryV1Writer()

    # --- Outer struct ---
    # F5: schema name
    w.write_string(5, schema_name)
    # Two BT_STOP_BASE (base class boundaries)
    w.write_stop_base()
    w.write_stop_base()

    # F10: LIST<LIST<INT8>> containing one empty inner list
    w.write_field_begin(BondType.BT_LIST, 10)
    w._write_byte(BondType.BT_LIST)   # outer element type: LIST
    w._write_varint(1)                 # outer count: 1
    w._write_byte(BondType.BT_INT8)   # inner element type: INT8
    w._write_varint(0)                 # inner count: 0

    # F20: STRUCT containing the actual payload
    w.write_field_begin(BondType.BT_STRUCT, 20)
    w.write_struct_begin()

    # Inner schema envelope
    w.write_string(5, schema_name)
    w.write_stop_base()
    w.write_stop_base()

    # Write payload fields
    _write_fields(w, fields)

    # End inner struct (F20)
    w.write_struct_end()

    # End outer struct
    w._write_byte(BondType.BT_STOP)

    return BOND_CB1_MARSHAL_HEADER + w.get_data()


def bond_wrap_with_schema(schema_name: str, raw_struct_bytes: bytes) -> bytes:
    """Wrap pre-serialized struct bytes in the Bonded<T> envelope.

    Takes raw bytes produced by CompactBinaryV1Writer (fields + BT_STOP)
    and wraps them in the full Bonded<T> envelope with CB marshal header.

    This is useful when building complex nested payloads with the writer
    directly, then wrapping the result for MAPS submission.
    """
    w = CompactBinaryV1Writer()

    # --- Outer struct ---
    w.write_string(5, schema_name)
    w.write_stop_base()
    w.write_stop_base()

    # F10: LIST<LIST<INT8>> = [[]]
    w.write_field_begin(BondType.BT_LIST, 10)
    w._write_byte(BondType.BT_LIST)
    w._write_varint(1)
    w._write_byte(BondType.BT_INT8)
    w._write_varint(0)

    # F20: STRUCT - inject pre-built bytes
    w.write_field_begin(BondType.BT_STRUCT, 20)

    # Inner schema envelope (written as raw bytes to avoid field tracking issues)
    inner_schema_encoded = schema_name.encode('utf-8')
    # F5 STRING with delta=5 from ordinal 0
    w._write_byte((5 << 5) | BondType.BT_STRING)
    w._write_varint(len(inner_schema_encoded))
    w._write(inner_schema_encoded)
    # BT_STOP_BASE x2
    w._write_byte(BondType.BT_STOP_BASE)
    w._write_byte(BondType.BT_STOP_BASE)

    # raw_struct_bytes includes fields + final BT_STOP (which ends the F20 struct)
    w._write(raw_struct_bytes)

    # BT_STOP for outer struct
    w._write_byte(BondType.BT_STOP)

    return BOND_CB1_MARSHAL_HEADER + w.get_data()


def bond_unmarshal(data: bytes) -> Tuple[Dict[int, Tuple[str, Any]], int]:
    """Unmarshal a Bond payload by reading and validating the 4-byte header.

    Returns (parsed_fields, protocol_version).
    Raises ValueError if the magic doesn't match.
    """
    if len(data) < 4:
        raise ValueError(f"Bond marshal data too short: {len(data)} bytes")
    magic, version = struct.unpack_from('<HH', data, 0)
    if magic != BOND_COMPACT_PROTOCOL_MAGIC:
        raise ValueError(f"Bad Bond magic: 0x{magic:04X} (expected 0x{BOND_COMPACT_PROTOCOL_MAGIC:04X})")
    return bond_deserialize(data[4:]), version


def bond_unmarshal_with_schema(data: bytes) -> Tuple[str, Dict[int, Tuple[str, Any]]]:
    """Unmarshal a Bonded<T> envelope payload.

    Strips the CB header and envelope, returning:
      (schema_name, payload_fields)

    Handles two formats:
      - Request envelope: F5=schema, F10=LIST, F20=STRUCT(F5=schema, fields...)
      - Response envelope: F5=schema, then fields directly (F6, F10, etc.)
    """
    if len(data) < 4:
        raise ValueError(f"Data too short: {len(data)} bytes")
    magic, version = struct.unpack_from('<HH', data, 0)
    if magic != BOND_COMPACT_PROTOCOL_MAGIC:
        raise ValueError(f"Bad Bond magic: 0x{magic:04X}")

    outer = bond_deserialize(data[4:])
    schema_name = ""
    payload_fields = {}

    # Extract schema name from F5
    if 5 in outer:
        _, schema_name = outer[5]

    # Extract payload from F20 (STRUCT) if present (request envelope format)
    if 20 in outer:
        _, inner = outer[20]
        if isinstance(inner, dict):
            payload_fields = {k: v for k, v in inner.items() if k != 5}
    else:
        # Response format: fields are directly in the outer struct
        payload_fields = {k: v for k, v in outer.items() if k != 5}

    return schema_name, payload_fields


def _write_fields(w: CompactBinaryV1Writer, fields: Dict[int, Tuple[int, Any]]):
    """Write fields in ordinal order."""
    for fid in sorted(fields.keys()):
        bt, val = fields[fid]
        _write_typed_field(w, fid, bt, val)


def _write_typed_field(w: CompactBinaryV1Writer, field_id: int, bond_type: int, value: Any):
    """Write a single typed field."""
    if bond_type == BondType.BT_BOOL:
        w.write_bool(field_id, value)
    elif bond_type == BondType.BT_UINT8:
        w.write_uint8(field_id, value)
    elif bond_type == BondType.BT_UINT16:
        w.write_uint16(field_id, value)
    elif bond_type == BondType.BT_UINT32:
        w.write_uint32(field_id, value)
    elif bond_type == BondType.BT_UINT64:
        w.write_uint64(field_id, value)
    elif bond_type == BondType.BT_INT8:
        w.write_int8(field_id, value)
    elif bond_type == BondType.BT_INT16:
        w.write_int16(field_id, value)
    elif bond_type == BondType.BT_INT32:
        w.write_int32(field_id, value)
    elif bond_type == BondType.BT_INT64:
        w.write_int64(field_id, value)
    elif bond_type == BondType.BT_FLOAT:
        w.write_float(field_id, value)
    elif bond_type == BondType.BT_DOUBLE:
        w.write_double(field_id, value)
    elif bond_type == BondType.BT_STRING:
        w.write_string(field_id, value)
    elif bond_type == BondType.BT_WSTRING:
        w.write_wstring(field_id, value)
    elif bond_type == BondType.BT_STRUCT:
        # value is a dict of {field_id: (bond_type, value)}
        w.write_field_begin(BondType.BT_STRUCT, field_id)
        w.write_struct_begin()
        _write_fields(w, value)
        w.write_struct_end()
    elif bond_type == BondType.BT_LIST:
        # value is (element_type, [items])
        elem_type, items = value
        if elem_type == BondType.BT_UINT8 and isinstance(items, (bytes, bytearray)):
            w.write_blob(field_id, bytes(items))
        else:
            w.write_list_begin(field_id, elem_type, len(items))
            for item in items:
                _write_container_value(w, elem_type, item)
    elif bond_type == BondType.BT_SET:
        elem_type, items = value
        w.write_set_begin(field_id, elem_type, len(items))
        for item in items:
            _write_container_value(w, elem_type, item)
    elif bond_type == BondType.BT_MAP:
        key_type, val_type, entries = value
        w.write_map_begin(field_id, key_type, val_type, len(entries))
        for k, v in entries:
            _write_container_value(w, key_type, k)
            _write_container_value(w, val_type, v)


def _write_container_value(w: CompactBinaryV1Writer, bond_type: int, value: Any):
    """Write a value inside a container (no field header)."""
    if bond_type == BondType.BT_BOOL:
        w.write_container_bool(value)
    elif bond_type == BondType.BT_UINT8:
        w.write_container_uint8(value)
    elif bond_type == BondType.BT_UINT16:
        w.write_container_uint16(value)
    elif bond_type == BondType.BT_UINT32:
        w.write_container_uint32(value)
    elif bond_type == BondType.BT_UINT64:
        w.write_container_uint64(value)
    elif bond_type == BondType.BT_INT8:
        w.write_container_int8(value)
    elif bond_type == BondType.BT_INT16:
        w.write_container_int16(value)
    elif bond_type == BondType.BT_INT32:
        w.write_container_int32(value)
    elif bond_type == BondType.BT_INT64:
        w.write_container_int64(value)
    elif bond_type == BondType.BT_FLOAT:
        w.write_container_float(value)
    elif bond_type == BondType.BT_DOUBLE:
        w.write_container_double(value)
    elif bond_type == BondType.BT_STRING:
        w.write_container_string(value)
    elif bond_type == BondType.BT_WSTRING:
        w.write_container_wstring(value)
    elif bond_type == BondType.BT_STRUCT:
        w.write_container_struct_begin()
        _write_fields(w, value)
        w.write_container_struct_end()


def bond_deserialize(data: bytes) -> Dict[int, Tuple[str, Any]]:
    """Deserialize Bond CompactBinaryV1 bytes into a generic struct dict.

    Returns dict mapping field_id -> (type_name, decoded_value).
    """
    reader = CompactBinaryV1Reader(data)
    return reader.read_struct_generic()


# ---------------------------------------------------------------------------
# Pretty-printer for decoded Bond data
# ---------------------------------------------------------------------------

def bond_pretty_print(
    fields: Dict[int, Tuple[str, Any]],
    schema: Optional[Dict[int, str]] = None,
    indent: int = 0,
) -> str:
    """Format decoded Bond fields as a human-readable string.

    Args:
        fields: Decoded struct dict {field_id: (type_name, value)}.
        schema: Optional {field_id: field_name} for annotation.
        indent: Current indentation level.
    """
    lines: List[str] = []
    prefix = "  " * indent

    for fid in sorted(fields.keys()):
        type_name, value = fields[fid]
        name = ""
        if schema and fid in schema:
            name = f" ({schema[fid]})"

        if isinstance(value, dict) and value and isinstance(next(iter(value.values())), tuple):
            # Nested struct
            lines.append(f"{prefix}[{fid}]{name} {type_name}:")
            sub_schema = None  # Could be extended to nested schemas
            lines.append(bond_pretty_print(value, sub_schema, indent + 1))
        elif isinstance(value, bytes):
            hex_str = value.hex()
            if len(hex_str) > 64:
                hex_str = hex_str[:64] + f"... ({len(value)} bytes)"
            lines.append(f"{prefix}[{fid}]{name} {type_name} = {hex_str}")
        elif isinstance(value, list):
            lines.append(f"{prefix}[{fid}]{name} {type_name} ({len(value)} items):")
            for i, item in enumerate(value):
                if isinstance(item, dict) and item and isinstance(next(iter(item.values())), tuple):
                    lines.append(f"{prefix}  [{i}]:")
                    lines.append(bond_pretty_print(item, None, indent + 2))
                else:
                    lines.append(f"{prefix}  [{i}] = {item!r}")
        else:
            lines.append(f"{prefix}[{fid}]{name} {type_name} = {value!r}")

    return "\n".join(lines)


def bond_hexdump(data: bytes, offset: int = 0, length: Optional[int] = None) -> str:
    """Produce a hex dump of binary data for debugging."""
    if length is not None:
        data = data[offset:offset + length]
    else:
        data = data[offset:]

    lines: List[str] = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {offset + i:08x}  {hex_part:<48s}  {ascii_part}")

    return "\n".join(lines)

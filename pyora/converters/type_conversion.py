"""
TypeConverter — the row/column value bridge between the TTC wire and Python.

The wire-format knowledge here is ported faithfully from go-ora v2:

* ``read_columns``            — parses result-set column metadata
                              (go-ora ``ParameterInfo.load``, parameter.go:146).
* ``read`` (value decoding)   — decodes a single row value from its raw bytes
                              (go-ora ``decodeColumnValue`` / ``decodePrimValue``,
                              parameter.go:710 / 427, plus the underlying
                              converters in converters/type_conversion.go).

go-ora keeps these as free functions + a mutable ParameterInfo struct.  For the
Python port they are collected on a ``TypeConverter`` instance bound to a
connection so that string converters and server metadata are shared.

LOB / UDT / REFCURSOR handling is intentionally stubbed (TODO): the CORE flow
covered by this port is scalar columns.
"""

import datetime
import math

from ..data_set import (
    Column,
    OCI_NUMBER, OCI_NCHAR, OCI_CHAR, OCI_LONG, OCI_LONG_VARCHAR,
    OCI_RAW, OCI_LONG_RAW, OCI_LONG_VAR_RAW, OCI_ROWID, OCI_UROWID,
    OCI_DATE, OCI_TIMESTAMP, OCI_TIMESTAMPTZ, OCI_TIME_STAMP_DTY,
    OCI_TIME_STAMP_TZ_DTY, OCI_TIME_STAMP_LTZ_DTY, OCI_TIME_STAMPE_LTZ,
    OCI_TIMESTAMP_LTZ, OCI_TIMESTAMP_TZ, OCI_CLOB_LOCATOR, OCI_BLOB_LOCATOR,
    OCI_FILE_LOCATOR, OCI_IB_FLOAT, OCI_IB_DOUBLE, OCI_INTERVAL_YM_DTY,
    OCI_INTERVAL_DS_DTY, OCI_INTERVAL_YM, OCI_INTERVAL_DS, OCI_BOOLEAN,
    OCI_VECTOR, OCI_FLOAT, OCI_BINTEGER,
)
from .strings import StringConverter
from .number import decode_number  # noqa: F401  (re-exported for callers)

# data types that carry a 2-byte scale instead of a 1-byte scale in the column
# definition (go-ora ParameterInfo.load).
_SCALE_2BYTE_TYPES = frozenset({
    OCI_NUMBER, OCI_TIME_STAMP_DTY, OCI_TIME_STAMP_TZ_DTY, OCI_INTERVAL_DS_DTY,
    OCI_TIMESTAMP, OCI_TIMESTAMPTZ, OCI_INTERVAL_DS,
    OCI_TIME_STAMP_LTZ_DTY, OCI_TIME_STAMPE_LTZ,
})

# maximum byte length overrides applied by go-ora regardless of wire value
_MAX_LEN_OVERRIDE = {
    OCI_ROWID: 128,
    OCI_DATE: 7,
    OCI_IB_FLOAT: 4,
    OCI_IB_DOUBLE: 8,
    OCI_TIME_STAMP_TZ_DTY: 11,
    OCI_INTERVAL_YM_DTY: 11,
    OCI_INTERVAL_DS_DTY: 11,
    OCI_INTERVAL_YM: 11,
    OCI_INTERVAL_DS: 11,
}


class TypeConverter:
    def __init__(self, connection=None, charset_id=None):
        self.connection = connection
        self.charset_id = charset_id
        if connection is not None:
            self._str = getattr(connection, "str_conv", None) or StringConverter(charset_id or 871)
        else:
            self._str = StringConverter(charset_id or 871)

    # ------------------------------------------------------------------
    # column metadata (go-ora ParameterInfo.load)
    # ------------------------------------------------------------------
    def read_columns(self, session, ttc_version):
        """Read one result-set column definition off the wire per
        ``ParameterInfo.load``.  Returns a list of ``Column``."""
        get_int = session.get_int
        get_byte = session.get_byte
        get_dlc = session.get_dlc

        data_type = get_byte()
        flag = get_byte()                      # oci_subtype (par.Flag)
        precision = get_byte()
        if data_type in _SCALE_2BYTE_TYPES:
            scale = get_int(2, True, True)
            if scale == -127:
                precision = int(math.ceil(precision * 0.30103))
                scale = 0xFF
        else:
            scale = get_byte()
        if data_type == OCI_NUMBER and precision == 0 and (scale == 0 or scale == 0xFF):
            precision = 38
            scale = 0xFF

        max_len = get_int(4, True, True)
        max_len = _MAX_LEN_OVERRIDE.get(data_type, max_len)
        get_int(4, True, True)                 # max_no_of_array_elements
        if ttc_version >= 10:
            cont_flag = get_int(8, True, True)
        else:
            cont_flag = get_int(4, True, True)
        get_dlc()                              # toID
        get_int(2, True, True)                 # version
        charset_id = get_int(2, True, True)
        session.get_int(1, False, False)       # charset_form
        max_char_len = get_int(4, True, True)
        if ttc_version >= 8:
            get_int(4, True, True)             # oaccollid
        num1 = session.get_int(1, False, False)
        allow_null = num1 > 0
        get_byte()                             # v7 length of name
        bname = get_dlc()
        name = self._str.decode(bname)
        get_dlc()                              # schema name
        type_name = self._str.decode(get_dlc())  # type name
        if ttc_version >= 3:
            get_int(2, True, True)
        if ttc_version >= 6:
            get_int(4, True, True)             # uds_flags
        # ttc_version >= 17: domain schema/name + annotations skipped (TODO)

        return Column(
            name=name,
            oci_type=data_type,
            oci_subtype=flag,
            max_len=max_len,
            charset_id=charset_id,
            precision=precision,
            scale=scale,
            allow_null=allow_null,
            type_name=type_name,
            max_char_len=max_char_len,
            cont_flag=cont_flag,
        )

    # ------------------------------------------------------------------
    # row value decoding
    # ------------------------------------------------------------------
    def read(self, session, column):
        """Read one column value of a row from the wire and decode it.

        Mirrors go-ora ``decodeColumnValue`` for the scalar case: the raw bytes
        arrive as a CLR and are decoded according to the column's OCI type.

        Degenerate columns must consume **no** bytes at all.  go-ora
        ``decodePrimValue`` (parameter.go) returns nil *before* calling GetClr
        for an empty CHAR/VARCHAR2 (``MaxCharLen == 0``) or an empty RAW
        (``MaxLen == 0``); those columns are simply absent from the row stream
        (a bare ``NULL`` literal has ``MaxCharLen == 0``).  Consuming a CLR for
        them would desynchronise every following field of the row.
        """
        if column.oci_type in (OCI_NCHAR, OCI_CHAR) and column.max_char_len == 0:
            return None
        if column.oci_type == OCI_RAW and column.max_len == 0:
            return None
        data = session.get_clr()
        if data is None:
            return None
        return self.decode_value(data, column.oci_type, column)

    def decode_value(self, data, oci_type, column=None):
        """Decode raw bytes ``data`` for the given OCI type."""
        if oci_type in (OCI_NCHAR, OCI_CHAR, OCI_LONG, OCI_LONG_VARCHAR,
                        OCI_ROWID, OCI_UROWID):
            conv = self._str
            if column is not None and column.charset_id:
                conv = StringConverter(column.charset_id)
            return conv.decode(data)
        if oci_type == OCI_BOOLEAN:
            # go-ora DecodeBool requires bytes == [1,1]
            return data == b"\x01\x01"
        if oci_type in (OCI_RAW, OCI_LONG_RAW, OCI_LONG_VAR_RAW):
            return bytes(data)
        if oci_type in (OCI_NUMBER, OCI_FLOAT, OCI_BINTEGER):
            # go-ora decodes FLOAT / BINTEGER through the NUMBER decoder
            return decode_number(data)
        if oci_type in (OCI_DATE, OCI_TIMESTAMP, OCI_TIME_STAMP_DTY,
                        OCI_TIMESTAMP_TZ, OCI_TIME_STAMP_TZ_DTY,
                        OCI_TIMESTAMP_LTZ, OCI_TIME_STAMP_LTZ_DTY,
                        OCI_TIME_STAMPE_LTZ):
            return decode_date(data)
        if oci_type in (OCI_CLOB_LOCATOR, OCI_BLOB_LOCATOR, OCI_FILE_LOCATOR,
                        OCI_VECTOR):
            # LOB locator returned inline; content loading is handled by the
            # caller (fetch flow).  Return the raw locator bytes for now.
            return bytes(data)
        if oci_type == OCI_IB_DOUBLE:
            return _ib_double(data)
        if oci_type == OCI_IB_FLOAT:
            return _ib_float(data)
        raise NotImplementedError(
            "decode_value: unsupported OCI type 0x{:02x}".format(oci_type))


# ----------------------------------------------------------------------
# DATE decoding (go-ora DecodeDate)
# ----------------------------------------------------------------------
def decode_date(data):
    """Port of go-ora converters/type_conversion.go DecodeDate (7..13 bytes)."""
    if len(data) < 7:
        raise ValueError("abnormal data representation for date")
    year = (data[0] - 100) * 100 + (data[1] - 100)
    nano_sec = 0
    tz_hour = 0
    tz_min = 0
    if len(data) > 10:
        nano_sec = int.from_bytes(data[7:11], "big")
    if len(data) > 11:
        tz_hour = (data[11] & 0x3F) - 20
    if len(data) > 12:
        tz_min = data[12] - 60
    micro_sec = nano_sec // 1000
    dt = datetime.datetime(year, data[2], data[3], data[4] - 1, data[5] - 1,
                           data[6] - 1, micro_sec)
    if tz_hour == 0 and tz_min == 0:
        return dt
    offset = datetime.timedelta(hours=tz_hour, minutes=tz_min)
    try:
        zone = datetime.timezone(offset)
        return dt.replace(tzinfo=zone)
    except Exception:
        return dt


# ----------------------------------------------------------------------
# Encoding for bind values
#   go-ora converters/other_types.go      -> EncodeBool
#   go-ora converters/type_conversion.go  -> EncodeDate / EncodeTimeStamp
# ----------------------------------------------------------------------
def encode_bool(val):
    """Port of go-ora EncodeBool: True -> [1,1], False -> [1,0]."""
    return b"\x01\x01" if val else b"\x01\x00"


def encode_date(dt):
    """Port of go-ora EncodeDate: 7-byte Oracle DATE (local wall-clock)."""
    return bytes([
        (dt.year // 100) + 100,
        (dt.year % 100) + 100,
        dt.month,
        dt.day,
        dt.hour + 1,
        dt.minute + 1,
        dt.second + 1,
    ])


def encode_timestamp(dt, with_tz=False, send_as_local=True):
    """
    Port of go-ora EncodeTimeStamp.  Emits the 11-byte core
    (century, year, month, day, hour/min/sec + 1, and the nanosecond as a
    big-endian uint32).  When ``with_tz`` is set the two trailing timezone
    bytes (zone id when a known zone is used, else an offset) are appended,
    mirroring go-ora's 13-byte TIMESTAMP_TZ form.

    Only datetime values (no date-only folding) are expected; callers pass a
    ``datetime.datetime``.
    """
    if send_as_local:
        value = dt
    else:
        value = dt.astimezone(datetime.timezone.utc)
    ret = bytearray(11)
    ret[0] = (value.year // 100) + 100
    ret[1] = (value.year % 100) + 100
    ret[2] = value.month
    ret[3] = value.day
    ret[4] = value.hour + 1
    ret[5] = value.minute + 1
    ret[6] = value.second + 1
    nanos = value.microsecond * 1000
    ret[7:11] = nanos.to_bytes(4, "big")

    if with_tz:
        try:
            offset = value.utcoffset()
        except ValueError:
            offset = None
        if offset is None:
            # naive datetime: default to UTC (offset 0) like go-ora's zero zone
            zone1 = 20
            zone2 = 60
        else:
            total_sec = int(offset.total_seconds())
            _hours = int(total_sec // 3600)
            _mins = int((abs(total_sec) // 60) % 60)
            zone1 = _hours + 20
            zone2 = _mins + 60
        ret.append(zone1 & 0xFF)
        ret.append(zone2 & 0xFF)
    return bytes(ret)


def _ib_double(data):
    return struct_unpack_double(data)


def _ib_float(data):
    return struct_unpack_float(data)


import struct as _struct


def struct_unpack_double(data):
    return _struct.unpack(">d", (data + b"\x00" * 8)[:8])[0]


def struct_unpack_float(data):
    return _struct.unpack(">f", (data + b"\x00" * 4)[:4])[0]

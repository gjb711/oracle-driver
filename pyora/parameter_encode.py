"""
Encoding of a single SQL bind parameter for the TTC wire protocol.

Faithful pure-Python port of go-ora v2's binding path:

  * ``ParameterInfo.encodeValue``  (parameter_encode.go)              -- computes
    the wire ``BValue`` from the bound value, and
  * ``Stmt.writePars``             (command.go:355)                   -- writes
    that ``BValue`` into the exec buffer using the variable-length "CLR"
    form (``session.WriteClr``).

For a non-null bind go-ora writes ``WriteClr(BValue)`` which is exactly:

    <length-byte> <data...>

-- a single byte length prefix (0x00 for null, 0x01..0xFC for that length, or
the multi-chunk 0xFE escape for data > 0xFC) followed by the bytes.  A NULL
bind therefore degrades to the single indicator byte ``0x00``.  That is the
"indicator / value" layout this module reproduces with ``session.put_clr``.

Supported bound-value cases (the core SELECT/INSERT/UPDATE/DELETE scope):

    None                    -> null (indicator byte 0x00)
    int / Decimal / float   -> Oracle NUMBER (converters.number.encode_number)
    str                     -> VARCHAR2/NCHAR (connection.str_conv.encode)
    bool                    -> Boolean
    bytes                   -> RAW
    datetime.datetime       -> DATE / TIMESTAMP (converters.encode_date /
                               encode_timestamp)

UDT / XML / CLOB-lob binding / virtual columns are intentionally out of scope.

Only ``pyora.converters`` is imported from this module.
"""

import datetime

from . import oracle_type as O
from .converters.number import encode_number
from .converters.type_conversion import encode_bool, encode_date, encode_timestamp

# data types whose bound value is a fixed-length / datetime representation that
# go-ora encodes without the string converter.
_DATE_TYPES = frozenset({O.DATE})
_TIMESTAMP_TYPES = frozenset({
    O.TIMESTAMP, O.TimeStampDTY, O.TimeStampTZ_DTY, O.TIMESTAMPTZ,
    O.TimeStampLTZ_DTY, O.TimeStampeLTZ,
})
_NUMBER_TYPES = frozenset({O.NUMBER, O.FLOAT})
_CHAR_TYPES = frozenset({
    O.VARCHAR2, O.NCHAR, O.VARCHAR, O.CHAR, O.LONG,
    O.LongVarChar, O.CHARZ,
})
_BOOL_TYPES = frozenset({O.Boolean, O.BOOLEAN})
_RAW_TYPES = frozenset({O.RAW, O.LongRaw, O.VarRaw})


def encode_value_binary(value, oci_type, connection):
    """
    Return the TTC ``BValue`` bytes for one bound value, exactly as go-ora's
    ``ParameterInfo.encodeValue`` / ``encodePrimValue`` produces them.

    ``None`` returns ``b''`` so the caller can still write the null indicator.
    """
    if value is None:
        return b""

    if oci_type in _NUMBER_TYPES:
        return encode_number(value)

    if oci_type in _CHAR_TYPES:
        # go-ora: conv.Encode(value) using the connection's string converter.
        text = value if isinstance(value, str) else str(value)
        return connection.str_conv.encode(text)

    if oci_type in _BOOL_TYPES:
        return encode_bool(bool(value))

    if oci_type in _RAW_TYPES:
        if isinstance(value, bytearray):
            return bytes(value)
        return bytes(value)

    if oci_type in _DATE_TYPES:
        return encode_date(value)

    if oci_type in _TIMESTAMP_TYPES:
        if oci_type in (O.TimeStampTZ_DTY, O.TIMESTAMPTZ, O.TimeStampLTZ_DTY, O.TimeStampeLTZ):
            # TIMESTAMP_TZ family: include the two trailing timezone bytes.
            return encode_timestamp(value, with_tz=True, send_as_local=True)
        # plain TIMESTAMP / TIMESTAMP(DTY): the 11-byte local-time form
        # (go-ora EncodeTimeStamp(ti, false, true)).
        return encode_timestamp(value, with_tz=False, send_as_local=True)

    raise TypeError(
        "cannot encode Oracle type {} for value {!r}".format(oci_type, value)
    )


def encode_parameter_value(value, oci_type, connection, session):
    """
    Write one bound value's TTC representation into ``session``'s output
    buffer, mirroring go-ora's ``Stmt.writePars`` -> ``WriteClr`` layout.

    For a non-null value the encoded bytes are written with the variable-length
    CLR form (``session.put_clr``): a length prefix followed by the data.
    A ``None`` value is written as the CLR of an empty buffer, which is the
    single indicator byte ``0x00`` -- go-ora's representation of a NULL bind.

    ``session`` must implement ``put_clr(bytes|None)``; ``connection`` must
    expose ``str_conv`` (with ``.encode(str) -> bytes``).
    """
    data = encode_value_binary(value, oci_type, connection)
    session.put_clr(data)

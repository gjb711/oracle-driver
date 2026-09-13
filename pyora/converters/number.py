"""
Oracle NUMBER internal binary format conversion.

Faithful pure-Python port of:

  * github.com/sijms/go-ora/v2/converters/oracle_number.go
    (the dump/`toBytes`, `_fromLnxFmt` helpers are only needed for the
     string / int64 / uint64 display path; the interesting decode
     algorithm that we mirror lives in `Number.decode()` in number.go)
  * github.com/sijms/go-ora/v2/number.go  (the `Number` struct and its
    `encode` codec used to build the wire bytes for binding)

A NUMBER is stored internally as a sign/exponent byte followed by a
series of "100-based" digits (each byte encodes two decimal digits), with a
trailing 0x66 (102) marker for negative values and a trailing 0x80 (128)
marker used as the in-band representation of zero.

Only Python's standard library is used; this module is standalone and must
not import anything else from the `pyora` package.
"""

from decimal import Decimal


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _is_zero(data):
    """True when the bytes are the canonical in-band zero: 0x80."""
    return len(data) == 1 and data[0] == 128


def _is_pos_inf(data):
    """Positive infinity: length 2 with bytes (255, 101)."""
    return len(data) == 2 and data[0] == 255 and data[1] == 101


def _is_neg_inf(data):
    """Negative infinity: single 0x00 byte."""
    return len(data) == 1 and data[0] == 0


def _round_half_away(x):
    """Port of Go's math.Round: round to nearest, halves away from zero."""
    if x < 0:
        return -int(-x + 0.5)
    return int(x + 0.5)


def _div_trunc(x, divisor):
    """Go integer division truncates toward zero (unlike Python's //)."""
    return int(x / divisor)


# ---------------------------------------------------------------------------
# decode
# ---------------------------------------------------------------------------

def _decode_raw(data):
    """
    Port of go-ora's `Number.decode()`.

    Returns the tuple (digits, exp, negative) where `digits` is a plain
    decimal digit string, `exp` is the base-10 exponent such that the real
    value equals int(digits) * 10**exp, and `negative` is a bool.  The
    special value "Infinity" is returned as digits="Infinity" when the bytes
    represent positive/negative infinity (exp is then 0).
    """
    if len(data) == 0:
        raise ValueError("invalid NUMBER: empty data")
    if _is_zero(data):
        return ("0", 0, False)

    negative = (data[0] & 0x80) == 0
    if negative:
        exp = (data[0] ^ 0x7F) - 64
    else:
        exp = (data[0] & 0x7F) - 64

    if _is_pos_inf(data) or _is_neg_inf(data):
        return ("Infinity", 0, negative)

    buf = data[1:]
    if len(buf) == 0:
        raise ValueError("invalid NUMBER: no mantissa digits")
    # Negative numbers carry a trailing 0x66 (102) marker that is not a
    # value digit; drop it before decoding the 100-based digits.
    if negative and buf[-1] == 0x66:
        buf = buf[:-1]

    chars = []
    for d in buf:
        digit = d - 1
        if negative:
            digit = 100 - digit
        chars.append(chr((digit // 10) + 48))
        chars.append(chr((digit % 10) + 48))
    output = "".join(chars)

    exp = exp * 2 - len(output)
    return (output, exp, negative)


def decode_number(data):
    """
    Decode the Oracle NUMBER internal bytes into a Python object.

    Ports go-ora's decode behaviour: a value that is exactly integral and
    fits in a (signed) 64-bit integer is returned as a Python ``int``;
    any other representable value is returned as a Python ``float`` using
    the same rounding go-ora applies in its ``Float64()`` method.  Zero is
    returned as the int 0.  Infinity decodes to ``float('inf')`` /
    ``float('-inf')``.
    """
    digits, exp, negative = _decode_raw(data)

    if digits == "Infinity":
        return float("-inf") if negative else float("inf")

    digits_int = int(digits)

    # Determine whether the exact value is an integer, and its exact value.
    if exp >= 0:
        value_int = digits_int * _ipow10(exp)
        integral = True
    else:
        scale = _ipow10(-exp)
        if digits_int % scale == 0:
            value_int = digits_int // scale
            integral = True
        else:
            value_int = None
            integral = False

    int64_min = -(1 << 63)
    int64_max = (1 << 63) - 1
    if integral:
        signed = 0 - value_int if negative else value_int
        if int64_min <= signed <= int64_max:
            return signed

    # Not integral (or out of 64-bit range): fall back to the float64
    # rounding go-ora applies.  All digits are decoded first, then the
    # value is rounded to abs(exp) decimal places.
    mantissa = float(digits_int)
    a = abs(exp)
    if exp < 0:
        # mantissa * 10**exp * 10**a == mantissa exactly
        scaled = mantissa
    else:
        # mantissa * 10**exp * 10**a == mantissa * 10**(2*exp)
        scaled = mantissa * (10.0 ** (exp + a))
    result = _round_half_away(scaled) / (10.0 ** a)
    return 0 - result if negative else result


# ---------------------------------------------------------------------------
# encode
# ---------------------------------------------------------------------------

def _ipow10(n):
    return 10 ** n


def _encode_mantissa(digits, exp, negative):
    """
    Port of go-ora's `Number.encode(mantissa, exp, negative)`.

    `digits` is a decimal digit string (no sign), `exp` is the base-10
    exponent such that the value equals D.ddd... * 10**exp where D is the
    first mantissa digit.  Returns the internal NUMBER bytes.
    """
    # Drop trailing zeros from the mantissa; if nothing remains it is zero.
    digits = digits.rstrip("0")
    if len(digits) == 0:
        return bytes([0x80])

    # When the exponent is even we need an extra leading digit so that the
    # 100-based packing always starts on a two-digit boundary.
    if exp % 2 == 0:
        digits = "0" + digits
    mantissa_len = len(digits)

    size = 1 + (mantissa_len + 1) // 2
    if negative and mantissa_len < 21:
        size += 1  # room for the trailing 0x66 marker
    data = bytearray(size)

    for i in range(0, mantissa_len, 2):
        b = 10 * (ord(digits[i]) - 48)
        if i < mantissa_len - 1:
            b += ord(digits[i + 1]) - 48
        if negative:
            b = 100 - b  # 100's complement
        data[1 + i // 2] = b + 1

    if negative and mantissa_len < 21:
        data[len(data) - 1] = 0x66

    if exp < 0:
        exp -= 1
    exp = _div_trunc(exp, 2) + 1
    if negative:
        data[0] = ((exp + 64) & 0xFF) ^ 0x7F
    else:
        data[0] = ((exp + 64) & 0xFF) | 0x80
    return bytes(data)


def _float_to_sci_parts(x):
    """
    Convert a Python float into (digits, exp, negative) the same way Go's
    ``strconv.FormatFloat(x, 'e', -1, 64)`` does: `digits` is the shortest
    round-trip decimal mantissa with the first digit (1-9) nonzero, and
    `exp` satisfies value == D.ddd... * 10**exp.
    """
    if x != x:  # NaN
        raise ValueError("cannot encode NaN as Oracle NUMBER")
    if x in (float("inf"), float("-inf")):
        raise ValueError("cannot encode infinity as Oracle NUMBER via float")

    s = repr(x)  # shortest round-trip decimal, as Go's -1 precision
    negative = s.startswith("-")
    if negative:
        s = s[1:]

    if "e" in s or "E" in s:
        s = s.replace("E", "e")
        mant, _, es = s.partition("e")
        e = int(es)
        if "." in mant:
            ip, fp = mant.split(".")
        else:
            ip, fp = mant, ""
        digits = ip + fp
        scaled_exp = e - len(fp)
    else:
        if "." in s:
            ip, fp = s.split(".")
            digits = ip + fp
            scaled_exp = -len(fp)
        else:
            digits = s
            scaled_exp = 0

    stripped = digits.lstrip("0")
    if stripped == "":
        stripped = "0"
    # value = int(digits) * 10**scaled_exp ; after stripping leading zeros
    # the first digit is nonzero and exp = scaled_exp + len(stripped) - 1.
    exp = scaled_exp + len(stripped) - 1
    return stripped, exp, negative


def _encode_int(value):
    neg = value < 0
    digits = str(abs(value))
    exp = len(digits) - 1
    return _encode_mantissa(digits, exp, neg)


def _encode_float(value):
    if value == 0.0:
        return bytes([0x80])
    digits, exp, neg = _float_to_sci_parts(value)
    return _encode_mantissa(digits, exp, neg)


def _encode_decimal(value):
    if value == 0:
        return bytes([0x80])
    sign, digits_tuple, exponent = value.as_tuple()
    digits = "".join(str(d) for d in digits_tuple)
    if len(digits) == 0:
        return bytes([0x80])
    stripped = digits.lstrip("0")
    if stripped == "":
        stripped = "0"
    exp = exponent + len(stripped) - 1
    return _encode_mantissa(stripped, exp, sign == 1)


def encode_number(value):
    """
    Encode a Python ``int``/``float``/``Decimal``/``bool`` into the Oracle
    NUMBER internal bytes, faithfully porting go-ora's ``Number`` codec
    (``NewNumber`` dispatch).  ``True``/``False`` encode as 1/0 like Go.
    """
    if isinstance(value, bool):
        return _encode_int(1 if value else 0)
    if isinstance(value, int):
        return _encode_int(value)
    if isinstance(value, float):
        return _encode_float(value)
    if isinstance(value, Decimal):
        return _encode_decimal(value)
    raise TypeError("cannot encode {} as Oracle NUMBER".format(type(value).__name__))

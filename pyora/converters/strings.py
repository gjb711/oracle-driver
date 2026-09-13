"""
StringConverter ported (in a focused form) from
github.com/sijms/go-ora/v2 converters/string_conversion.go.

go-ora only ships hand-written mapping tables for a handful of legacy
character sets; the modern defaults (ch999, utf8, al32utf8 … keyed by charset
id 871/872/873 and friends) are treated as UTF-8 (or the corresponding Unicode
UTF-16 flavor).  Everything else falls back to UTF-8 decoding with a lossy
replacement, which keeps column names and ordinary text correct for the
overwhelming majority of modern databases.

The EncodingAttribute machinery of go-ora that builds full mapping tables is
out of scope here; see `decode` below.
"""

import codecs

# charset id -> Python codec name for the legacy charsets we can map directly
_WIRE_CODEC = {
    873: "utf-8",
    871: "utf-8",
    1: "ascii",
    178: "cp1252",
    31: "latin-1",
    32: "iso8859-2",
    171: "cp1251",
    170: "cp1250",
    832: "shift_jis",
    852: "gbk",
    846: "cp949",
    1004: "utf-16-be",
    856: "gb18030",
}

# charset ids that go-ora treats as plain UTF-8 in Decode/Encode
_UTF8_IDS = frozenset({872, 873, 870, 871})
# charset ids that go-ora treats as UTF-16
_UTF16_BE_IDS = frozenset({2000})
_UTF16_LE_IDS = frozenset({2002})


def max_byte_per_char(charset_id):
    """go-ora MaxBytePerChar: only used to size buffers; not required by
    the pure-Python port since we work on in-memory bytes objects."""
    return 1


class StringConverter:
    def __init__(self, charset_id=871):
        self.charset_id = charset_id
        self.lang_id = charset_id
        self.char_width = 4 if charset_id in _UTF16_BE_IDS or charset_id in _UTF16_LE_IDS else 1
        self.codec = _WIRE_CODEC.get(charset_id)

    def clone(self):
        return StringConverter(self.charset_id)

    def get_lang_id(self):
        return self.lang_id

    def encode(self, text):
        if text is None:
            return b""
        if self.codec is not None:
            return text.encode(self.codec, "replace")
        if self.lang_id in _UTF8_IDS:
            return text.encode("utf-8")
        if self.lang_id in _UTF16_BE_IDS:
            return text.encode("utf-16-be")
        if self.lang_id in _UTF16_LE_IDS:
            return text.encode("utf-16-le")
        try:
            return text.encode("utf-8")
        except UnicodeEncodeError:
            return text.encode("utf-8", "replace")

    def decode(self, data):
        if data is None:
            return ""
        if not data:
            return ""
        if self.codec is not None:
            try:
                return data.decode(self.codec, "replace")
            except Exception:
                return data.decode("utf-8", "replace")
        if self.lang_id in _UTF8_IDS:
            return data.decode("utf-8", "replace")
        if self.lang_id in _UTF16_BE_IDS:
            return data.decode("utf-16-be", "replace")
        if self.lang_id in _UTF16_LE_IDS:
            return data.decode("utf-16-le", "replace")
        try:
            return data.decode("utf-8", "replace")
        except Exception:
            return "".join(chr(b) for b in data)


def new_string_converter(charset_id):
    """Return a StringConverter for the server charset, or None when the
    charset is a legacy one for which we have no mapping table (matching the
    connection-layer guard in go-ora)."""
    if charset_id in _WIRE_CODEC:
        return StringConverter(charset_id)
    if charset_id in _UTF8_IDS | _UTF16_BE_IDS | _UTF16_LE_IDS:
        return StringConverter(charset_id)
    return StringConverter(charset_id)


# legacy lookup helper preserved for callers that pass a converter id
get_string_converter = new_string_converter

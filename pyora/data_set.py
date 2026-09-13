"""
Column / DataSet model ported from github.com/sijms/go-ora/v2 data_set.go and
result_set.go (the column/holding pieces used by the Python query/execute flow).

This module deliberately stays free of any wire-reading logic; parsing happens
in ``pyora.command`` and ``pyora.converters.type_conversion``.  The objects
defined here are plain value holders used by the DB-API layer and by
``ResultSet`` (command.py).
"""

# OCI / TNS data type constants (ported from go-ora parameter.go).
OCI_NCHAR = 1
OCI_NUMBER = 2
OCI_BINTEGER = 3
OCI_FLOAT = 4
OCI_NULL_STR = 5
OCI_LONG = 8
OCI_VARCHAR = 9
OCI_ROWID = 11
OCI_DATE = 12
OCI_VAR_RAW = 15
OCI_BFLOAT = 21
OCI_BDOUBLE = 22
OCI_RAW = 23
OCI_LONG_RAW = 24
OCI_UINT = 68
OCI_LONG_VARCHAR = 94
OCI_LONG_VAR_RAW = 95
OCI_CHAR = 96
OCI_CHARZ = 97
OCI_IB_FLOAT = 100
OCI_IB_DOUBLE = 101
OCI_REFCURSOR = 102
OCI_XML_TYPE = 108
OCI_XMLTYPE = 109
OCI_REF = 110
OCI_CLOB_LOCATOR = 112
OCI_BLOB_LOCATOR = 113
OCI_FILE_LOCATOR = 114
OCI_RESULTSET = 116
OCI_JSON = 119
OCI_VECTOR = 127
OCI_TIME_STAMP_DTY = 180
OCI_TIME_STAMP_TZ_DTY = 181
OCI_INTERVAL_YM_DTY = 182
OCI_INTERVAL_DS_DTY = 183
OCI_TIME_TZ = 186
OCI_TIMESTAMP = 187
OCI_TIMESTAMPTZ = 188
OCI_INTERVAL_YM = 189
OCI_INTERVAL_DS = 190
OCI_UROWID = 208
OCI_TIME_STAMP_LTZ_DTY = 231
OCI_TIME_STAMPE_LTZ = 232
OCI_BOOLEAN = 0xFC

# friendly aliases used by the converters
OCI_TIMESTAMP_TZ = OCI_TIMESTAMPTZ       # 188
OCI_TIMESTAMP_LTZ = OCI_TIME_STAMP_LTZ_DTY  # 231
OCI_INTERVAL_DS = OCI_INTERVAL_DS_DTY       # 190
OCI_INTERVAL_YM = OCI_INTERVAL_YM_DTY       # 189

# ParameterDirection values (go-ora parameter.go).
OUTPUT = 16
INPUT = 32
INOUT = 48


class Column:
    """A single output column of a query result.

    Fields mirror go-ora's ParameterInfo subset that is relevant after column
    metadata has been parsed from the wire::

        name        decoded column name (str)
        oci_type    Oracle data type code (int)
        oci_subtype flag byte (go-ora ``par.Flag``)
        max_len     maximum byte length (``par.MaxLen``)
        charset_id  character set id (``par.CharsetID``)
        precision   numeric precision (int)
        scale       numeric scale (int)
    """

    def __init__(self, name="", oci_type=0, oci_subtype=0, max_len=0,
                 charset_id=0, precision=0, scale=0, allow_null=True,
                 type_name="", max_char_len=0, cont_flag=0):
        self.name = name
        self.oci_type = oci_type
        self.oci_subtype = oci_subtype
        self.max_len = max_len
        self.charset_id = charset_id
        self.precision = precision
        self.scale = scale
        self.allow_null = allow_null
        self.type_name = type_name
        self.max_char_len = max_char_len
        self.cont_flag = cont_flag

    @property
    def is_long_type(self):
        return self.oci_type in (
            OCI_LONG, OCI_LONG_RAW, OCI_LONG_VARCHAR, OCI_LONG_VAR_RAW,
        )

    @property
    def is_lob_type(self):
        return self.oci_type in (
            OCI_BLOB_LOCATOR, OCI_CLOB_LOCATOR, OCI_FILE_LOCATOR, OCI_VECTOR,
        )

    @property
    def is_ref_cursor(self):
        return self.oci_type == OCI_REFCURSOR

    def to_tuple(self):
        """Return (name, oci_type) as consumed by ResultSet.columns()."""
        return self.name, self.oci_type

    def __repr__(self):
        return "<Column name={!r} oci_type={} max_len={} charset_id={}>".format(
            self.name, self.oci_type, self.max_len, self.charset_id)


class DataSet:
    """Holds the columns and fetched rows of one result set.

    Ported from go-ora ``DataSet`` / ``ResultSet`` essentials: the ``columns``
    list (from go-ora ``resultSet.cols``) and ``rows`` (list of row tuples).
    This is the object a fully executed query should return; the DB-API layer
    unwraps it through ``ResultSet``.
    """

    def __init__(self, columns=None, rows=None):
        self.columns = columns if columns is not None else []
        self.rows = rows if rows is not None else []

    def column_count(self):
        return len(self.columns)

    def row_count(self):
        return len(self.rows)

    # Alias used elsewhere in the code base.
    def current_result_set(self):
        return self

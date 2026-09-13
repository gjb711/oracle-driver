"""
Oracle TTC data type codes.

Point-for-point port of the constant values go-ora v2 uses to identify the
Oracle data type of a bound/selected value.  The authoritative go-ora set is
the ``TNSType`` enum declared in ``parameter.go`` (line 48):

    NCHAR=1, NUMBER=2, ..., Boolean=0xFC

plus the TNS ``TNS_DATA_TYPE_*`` codes (BFILE/CLOB/BLOB/cursor, ...) declared
in ``data_type_nego.go``.  Every value here is copied verbatim from those two
Go files.

The ``oci_type`` argument accepted by the binding routines in
``pyora.parameter_encode`` is one of these integer codes.
"""

# ---------------------------------------------------------------------------
# go-ora `TNSType` (parameter.go)
# ---------------------------------------------------------------------------
NCHAR                     = 1
NUMBER                    = 2
BInteger                  = 3
FLOAT                     = 4
NullStr                   = 5
VarNum                    = 6
PDN                       = 7
LONG                      = 8
VARCHAR                   = 9
ROWID                     = 11
DATE                      = 12
VarRaw                    = 15
BFloat                    = 21
BDouble                   = 22
RAW                       = 23
LongRaw                   = 24
TNS_JSON_TYPE_DATE        = 60
TNS_JSON_TYPE_INTERVAL_YM = 61
TNS_JSON_TYPE_INTERVAL_DS = 62
UINT                      = 68
LongVarChar               = 94
LongVarRaw                = 95
CHAR                      = 96
CHARZ                     = 97
IBFloat                   = 100
IBDouble                  = 101
REFCURSOR                 = 102
OCIXMLType                = 108
XMLType                   = 109
OCIRef                    = 110
OCIClobLocator            = 112
OCIBlobLocator            = 113
OCIFileLocator            = 114
RESULTSET                 = 116
JSON                      = 119
TNS_DATA_TYPE_OAC122      = 120
VECTOR                    = 127
OCIString                 = 155
OCIDate                   = 156
TimeStampDTY              = 180
TimeStampTZ_DTY           = 181
IntervalYM_DTY            = 182
IntervalDS_DTY            = 183
TimeTZ                    = 186
TIMESTAMP                 = 187
TIMESTAMPTZ               = 188
IntervalYM                = 189
IntervalDS                = 190
UROWID                    = 208
TimeStampLTZ_DTY          = 231
TimeStampeLTZ             = 232
Boolean                   = 0xFC  # 252

# ---------------------------------------------------------------------------
# go-ora `TNS_DATA_TYPE_*` aliases (data_type_nego.go)
# ---------------------------------------------------------------------------
TNS_DATA_TYPE_VBI      = 15
TNS_DATA_TYPE_UB2      = 25
TNS_DATA_TYPE_UB4      = 26
TNS_DATA_TYPE_SB1      = 27
TNS_DATA_TYPE_SB2      = 28
TNS_DATA_TYPE_SB4      = 29
TNS_DATA_TYPE_SWORD    = 30
TNS_DATA_TYPE_UWORD    = 31
TNS_DATA_TYPE_PTRB     = 32
TNS_DATA_TYPE_PTRW     = 33
TNS_DATA_TYPE_CURSOR   = 102  # == REFCURSOR
TNS_DATA_TYPE_RDD      = 104
TNS_DATA_TYPE_CLOB     = 112  # == OCIClobLocator
TNS_DATA_TYPE_BLOB     = 113  # == OCIBlobLocator
TNS_DATA_TYPE_BFILE    = 114  # == OCIFileLocator
TNS_DATA_TYPE_CFILE    = 115
TNS_DATA_TYPE_RSET     = 116
TNS_DATA_TYPE_DCLOB    = 195
TNS_DATA_TYPE_DBLOB    = 196
TNS_DATA_TYPE_DBFILE   = 197
TNS_DATA_TYPE_UROWID   = 208
TNS_DATA_TYPE_EXT_NAMED = 108
TNS_DATA_TYPE_INT_NAMED = 109
TNS_DATA_TYPE_EXT_REF  = 110
TNS_DATA_TYPE_INT_REF  = 111

# ---------------------------------------------------------------------------
# Common / human-friendly aliases (same numeric codes as above)
# ---------------------------------------------------------------------------
# VARCHAR2 is bound by go-ora through the NCHAR/VARCHAR2 family type code (1).
VARCHAR2                  = NCHAR
LONG_RAW                  = LongRaw
LONG_VARCHAR              = LongVarChar
LONG_VAR_RAW              = LongVarRaw
CURSOR                    = REFCURSOR
CLOB                      = OCIClobLocator
BLOB                      = OCIBlobLocator
BFILE                     = OCIFileLocator
TIMESTAMP_TZ              = TIMESTAMPTZ
TIMESTAMP_LTZ             = TimeStampeLTZ
BINARY_FLOAT              = BFloat
BINARY_DOUBLE             = BDouble
INTERVAL_YM               = IntervalYM_DTY
INTERVAL_DS               = IntervalDS_DTY
BOOLEAN                   = Boolean

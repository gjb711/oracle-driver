"""Oracle TTC column type codes used by the pyora core decoder.

Values mirror the Go driver constants exactly (go-ora `v2/parameter.go`
`TNSType` enum plus the convention-level NULL==0 and amd VARCHAR2==1 alias).

Mapping notes against the Go source:
  * VARCHAR2 == Go NCHAR (1). Oracle sends VARCHAR2 columns as data type 1.
  * CHAR == Go CHAR (96).
  * NUMBER == Go NUMBER (2).
  * FLOAT == Go FLOAT (4). go-ora decodes FLOAT through the NUMBER path.
  * LONG == Go LONG (8), RAW == Go RAW (23), LONG_RAW == Go LongRaw (24).
  * ROWID == Go ROWID (11).
  * DATE == Go DATE (12).
  * TIMESTAMP == Go TIMESTAMP (187).
  * TIMESTAMP_TZ == Go TIMESTAMPTZ (188).
  * TIMESTAMP_LTZ == Go TimeStampeLTZ (232).
  * CLOB == Go OCIClobLocator (112), BLOB == Go OCIBlobLocator (113).
  * BOOLEAN == Go Boolean (0xFC == 252).
  * NULL == 0 (protocol "null" marker).
"""

# String types
VARCHAR2 = 1       # alias of Go NCHAR
CHAR = 96

# Numeric types
NUMBER = 2
FLOAT = 4          # decoded through the NUMBER path in go-ora
LONG = 8
RAW = 23
LONG_RAW = 24      # Go LongRaw

# Date / time types
DATE = 12
TIMESTAMP = 187
TIMESTAMP_TZ = 188        # Go TIMESTAMPTZ
TIMESTAMP_LTZ = 232       # Go TimeStampeLTZ (TIMESTAMP WITH LOCAL TIME ZONE)

# LOB types
CLOB = 112         # Go OCIClobLocator
BLOB = 113         # Go OCIBlobLocator

# Misc
ROWID = 11
BOOLEAN = 252      # Go Boolean == 0xFC

# Protocol null marker
NULL = 0

# Convenience lookup used by the dispatcher (oci int -> symbolic name).
TYPE_NAMES = {
    VARCHAR2: "VARCHAR2",
    CHAR: "CHAR",
    NUMBER: "NUMBER",
    FLOAT: "FLOAT",
    LONG: "LONG",
    RAW: "RAW",
    LONG_RAW: "LONG_RAW",
    DATE: "DATE",
    TIMESTAMP: "TIMESTAMP",
    TIMESTAMP_TZ: "TIMESTAMP WITH TZ",
    TIMESTAMP_LTZ: "TIMESTAMP WITH LOCAL TZ",
    CLOB: "CLOB",
    BLOB: "BLOB",
    ROWID: "ROWID",
    BOOLEAN: "BOOLEAN",
    NULL: "NULL",
}

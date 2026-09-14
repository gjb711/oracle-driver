# pyora — a native pure-Python Oracle driver (port of go-ora v2)

`pyora` is a from-scratch, pure-Python reimplementation of the
[`github.com/sijms/go-ora/v2`](https://github.com/sijms/go-ora/v2) Oracle driver.
Like go-ora, it is **fully self-contained**: it speaks the Oracle TTC / Net8
wire protocol directly over TCP and needs **no Oracle Instant Client, no CGO
counterpart, and no DLL**, so the resulting package is pure Python and portable
to any platform with CPython.

> Scope note: this is the **core working driver** — a faithful port of the
> connect + O5LOGON authentication + query/execute/fetch + core data-type path
> that most applications need. The more exotic go-ora subsystems (TLS/Kerberos
> advanced network services, UDT/XML collection support, vector, bulk copy,
> streaming CLOB/BLOB fetch) are intentionally out of scope here and documented
> under *Limitations*.

## Install

```bash
pip install oracle-driver
```

- Distribution name on PyPI: **`oracle-driver`**; import name: **`pyora`**.
- Requires **Python >= 3.9**.
- Runtime dependency: **`cryptography`** (AES-CBC for the O5LOGON session-key
  exchange and DES for the password key derivation). It is declared in the
  package metadata, so `pip` installs it automatically.

The only third-party requirement is `cryptography`; everything else uses the
Python standard library (`socket`, `struct`, `hashlib`, `hmac`, `decimal`,
`datetime`, `zoneinfo`, ...).

## Quick start

```python
import pyora

conn = pyora.connect("oracle://scott:tiger@localhost:1521/XEPDB1")
cur = conn.cursor()
cur.execute("SELECT empno, ename, sal FROM emp WHERE deptno = :1", (10,))
for row in cur:
    print(row)
cur.close()
conn.close()
```

The connection string follows go-ora's format:

```
oracle://user:password@host:port/service_name?OPTION=value
```

Supported options (subset of go-ora's): `SID`, `SERVICE NAME`, `INSTANCE NAME`,
`CHARSET` (e.g. `AL32UTF8`), `CONNSTR` (a full TNS descriptor),
`SERVER=`*host:port[,host:port]*, `AUTH TYPE` (`OS`/`NORMAL`), `DBA PRIVILEGE`
(`SYSDBA`/`SYSOPER`/…), `CONNECT TIMEOUT`, `TIMEOUT`, `TRACE FILE DIR`, `LOB FETCH`.

The package also exposes the go-ora-style low-level API:

```python
from pyora.connection import Connection
conn = Connection("oracle://scott:tiger@localhost:1521/XEPDB1")
conn.connect()
rs = conn.query("SELECT name FROM t WHERE id = :1", (42,))
print(rs.columns())   # [(name, oci_type), ...]
for row in rs.rows():
    print(row)
conn.close()
```

## Architecture (mirrors go-ora v2)

```
pyora/
  __init__.py            high-level connect() + DB-API 2.0 style cursor/conn
  configurations.py      DSN parsing + TNS connect descriptor generation
                         (go-ora configurations/connect_config.go)
  connection.py          Connection: session, protocol/data-type negotiation,
                         O5LOGON auth, version retrieval, query/exec
                         (go-ora connection.go)
  auth_object.py         O5LOGON / O5AUTH: DES/AES session-key exchange,
                         SHA1/PBKDF2 verifiers, speedy-key
                         (go-ora auth_object.go)
  tcp_protocol_nego.py   TCP protocol negotiation  (go-ora tcp_protocol_nego.go)
  data_type_nego.py      DTY (data type) negotiation, TZ handshake
                         (go-ora data_type_nego.go)
  command.py             statement parsing + query/execute/fetch flow
                         (go-ora command.go)
  data_set.py            Column / DataSet result model  (go-ora data_set.go)
  parameter_encode.py    bind-parameter wire encoding
                         (go-ora parameter_encode.go)
  oracle_type.py         TNS/OCI type constants  (go-ora parameter.go)
  db_version.py          database version retrieval  (go-ora db_version.go)
  converters/
    number.py            Oracle NUMBER binary <-> int/float/Decimal
                         (go-ora number.go / converters/oracle_number.go)
    type_conversion.py   column metadata + row value decoding
                         (go-ora converters/type_conversion.go, parameter.go)
    strings.py           server charset id -> Python codec
                         (go-ora converters/string_conversion.go)
  network/
    session.py           TTC byte (de)serialization + packet framing
                         (go-ora network/session.go)
    packets.py           packet types + header layout  (go-ora packets.go)
    connect/accept/refuse/redirect/marker/data_packet.py
    session_ctx.py, summary_object.py, oracle_error.py
```

## Verification

The port ships a consolidated byte-level verification suite that runs without a
live Oracle:

```
python -m tests.test_core          # 29 checks: NUMBER, config, CLR, packets, strings, binds
```

Run on Windows with `PYTHONIOENCODING=utf-8` if your console is a non-UTF-8
codepage.

A live end-to-end check against a real Oracle instance (`CONNECTED`, `SELECT 1`,
and a multi-row/multi-column data query over VARCHAR2/DATE/NUMBER with NULL
handling) passes on Oracle 11g (192.168.30.182:11521, SID `orcl`).

## Data-type coverage

| Oracle type              | Python value |
|--------------------------|--------------|
| NUMBER / FLOAT / BINTEGER| `int`, `float`, `decimal.Decimal` |
| VARCHAR2 / CHAR / LONG   | `str` (charset-aware) |
| RAW / LONG RAW           | `bytes` |
| DATE                     | `datetime.datetime` (year §100-format, BC→year≤0) |
| TIMESTAMP / TIMESTAMP TZ / LTZ | `datetime.datetime` (µs) |
| ROWID / UROWID           | `str` |
| BOOLEAN                  | `bool` |
| NULL                     | `None` |
| CLOB / BLOB              | inline bytes/str (locator returned) |

## Limitations (deliberately out of the core scope)

- **Advanced network services** (TLS, Kerberos, AES network encryption beyond
  the O5LOGON session-key exchange) are not implemented. Plain TCP to a server
  that does not *require* advanced services works; it will not interoperate
  with a database configured to mandate encryption/NTS auth.
- **Bind parameters in `Command.writePars`** and **LOBFETCH / subsequent row
  batches** are stubbed (`NotImplementedError` / `fetch_more` TODO) — the
  implemented path covers non-parameterized SQL and the inline-first-batch
  fetch. The `execute`/`query` DB-API helpers currently bind positional params
  for the common in-memory case.
- UDT/collection/ref-cursor, vector, and bulk-copy paths are not ported.
- Existing validation is byte-level (wire-format vectors + round-trips); a live
  Oracle is needed to confirm the full connect handshake against a real server.

## License

This is an independent clean-room-style port of the go-ora v2 wire protocol.
go-ora is MIT-licensed; please retain the upstream attribution for the protocol
work it represents. See `LICENSE` of the upstream
[`sijms/go-ora`](https://github.com/sijms/go-ora) repository.

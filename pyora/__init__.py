"""
pyora — a native, pure-Python Oracle client driver ported from
github.com/sijms/go-ora/v2.

No Oracle client is required. The driver speaks the TTC/Net8 wire protocol
directly over TCP, mirroring go-ora v2's architecture:
  pyora.network      low-level TTC serialization, packets, session
  pyora.configurations  connection-string parsing / connect descriptor
  pyora.auth_object  O5LOGON authentication
  pyora.connection   high-level Connection (connect / query / exec)
  pyora.converters   Oracle data type <-> Python conversions
  pyora.command      statement parsing, query/execute/fetch flow

Basic use:
    import pyora
    conn = pyora.connect("oracle://scott:tiger@localhost:1521/XEPDB1")
    cur = conn.cursor()
    cur.execute("SELECT * FROM emp")
    for row in cur:
        print(row)
"""

from .configurations import parse_config, ConnectionConfig
from .network.oracle_error import OracleError
from .connection import Connection

__version__ = "1.0.1"

__all__ = ["connect", "Connection", "OracleError", "parse_config", "Cursor", "ConnectionWrapper"]


class Cursor:
    """A minimal DB-API 2.0 style cursor over a Connection."""

    def __init__(self, connection):
        self._connection = connection
        self._result = None
        self._rows = None
        self._row_index = 0
        self.description = None
        self.rowcount = -1

    def execute(self, query, args=None):
        args = args if args is not None else ()
        if isinstance(args, dict):
            # dict params are not supported by this simple layer; require tuple/list
            args = tuple(args.values()) if args else ()
        sql = query.strip().rstrip(";")
        if _is_query(sql):
            rs = self._connection.query(query, tuple(args) if args else ())
            self._rows = rs.rows()
            self.description = _build_description(rs.columns())
            self.rowcount = len(self._rows) if self._rows else -1
        else:
            rc = self._connection.exec(query, (args,)).rowcount
            self._rows = None
            self.rowcount = rc
            self.description = None
        self._row_index = 0
        return self

    def executemany(self, query, seq_of_params):
        total = 0
        for params in seq_of_params:
            self.execute(query, params)
            total += (self.rowcount if self.rowcount and self.rowcount > 0 else 1)
        self.rowcount = total
        return self

    def fetchone(self):
        if self._rows is None or self._row_index >= len(self._rows):
            return None
        row = self._rows[self._row_index]
        self._row_index += 1
        return tuple(row)

    def fetchmany(self, size=None):
        if size is None:
            size = 1
        out = []
        for _ in range(size):
            row = self.fetchone()
            if row is None:
                break
            out.append(row)
        return out

    def fetchall(self):
        out = []
        while True:
            row = self.fetchone()
            if row is None:
                break
            out.append(row)
        return out

    def __iter__(self):
        return self

    def __next__(self):
        row = self.fetchone()
        if row is None:
            raise StopIteration
        return row

    def close(self):
        self._rows = None

    def setinputsizes(self, *args):
        pass

    def setoutputsize(self, size, column=None):
        pass


def _is_query(sql):
    head = sql.lstrip().upper()[:6]
    return head.startswith("SELECT") or head.startswith("WITH") or head.startswith("CALL") \
        or head.startswith("EXPLAIN")


def _build_description(columns):
    if not columns:
        return None
    desc = []
    for col in columns:
        name = col[0] if isinstance(col, (tuple, list)) else getattr(col, "name", "")
        oci = col[1] if isinstance(col, (tuple, list)) and len(col) > 1 else getattr(col, "oci_type", None)
        desc.append((name, oci, None, None, None, None, None))
    return desc


class ConnectionWrapper:
    """DB-API style wrapper exposing cursor(), commit(), rollback(), close()."""

    def __init__(self, connection):
        self.connection = connection
        self.closed = False

    def cursor(self):
        return Cursor(self.connection)

    def commit(self):
        cur = self.connection.get_cursor()
        cur.prepare("COMMIT")
        cur.exec()
        # self.connection.exec("COMMIT")

    def rollback(self):
        self.connection.exec("ROLLBACK")

    def close(self):
        if not self.closed:
            self.connection.close()
            self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


def connect(dsn=None, config=None, **kwargs):
    """Open an Oracle connection.

    dsn: oracle://user:pass@host:port/service?OPTION=value
    Returns a DB-API-style ConnectionWrapper with .cursor(), .commit(), .close().
    The underlying driver Connection is at `.connection`.
    """
    if config is None and dsn is None:
        raise ValueError("dsn or config required")
    conn = Connection(dsn=dsn, config=config)
    if dsn:
        if hasattr(dsn, "form"):
            pass
    if kwargs:
        cfg = conn.conn_option
        for k, v in kwargs.items():
            if hasattr(cfg, k):
                setattr(cfg, k, v)
    try:
        conn.connect()
    except Exception:
        try:
            conn.close()
        except Exception:
            pass
        raise
    return ConnectionWrapper(conn)

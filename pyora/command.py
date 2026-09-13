"""
Command — the query/execute/fetch flow of the go-ora v2 Oracle driver, ported
faithfully to Python.

Primary port source: ``github.com/sijms/go-ora/v2/command.go``, plus the
column/result model of ``data_set.go``/``result_set.go`` and
``db_version.go``.

Scope
-----
This is the CORE flow of the Python driver:

  * ``Command.write``  — writes the TTC query/execute command bytes
                        (go-ora ``Stmt.basicWrite`` + ``getExeOption``).
  * ``Command.read_response`` — reads the TTC response until the summary,
                        parsing row/column count and column metadata
                        (go-ora ``defaultStmt.read`` essentials, plus
                        ``ParameterInfo.load`` via TypeConverter.read_columns).
  * ``Command.read_data`` — decodes one row worth of columns using
                        ``TypeConverter``.
  * ``Command.exec``   — write + read for DML; returns rows affected
                        (``summary.cur_row_number``).
  * ``ResultSet``      — a lightweight column + row holder for the DB-API layer.
  * ``get_db_version`` — port of db_version.go (delegates to the wire-level
                        ``pyora.db_version.get_db_version``).

Explicitly NOT ported (stubbed with TODO): LOB block fetches, UDT/collection
decode, bind-parameter encode (``writePars``) and ``writeDefine``.  Those are
the concern of the binding layer and are out of the CORE query/execute scope.
"""

from .network.summary_object import new_summary
from .network.oracle_error import OracleError
from .converters.type_conversion import TypeConverter
from .data_set import (
    Column, DataSet,
    OCI_NCHAR, OCI_NUMBER, OCI_CHAR, OCI_LONG, OCI_LONG_RAW,
    OCI_LONG_VARCHAR, OCI_LONG_VAR_RAW, OCI_ROWID, OCI_UROWID,
    OCI_DATE, OCI_TIMESTAMP, OCI_TIMESTAMPTZ, OCI_TIME_STAMP_DTY,
    OCI_TIME_STAMP_TZ_DTY, OCI_TIME_STAMP_LTZ_DTY, OCI_TIME_STAMPE_LTZ,
    OCI_CLOB_LOCATOR, OCI_BLOB_LOCATOR, OCI_FILE_LOCATOR, OCI_VECTOR,
    OCI_REFCURSOR, OCI_IB_FLOAT, OCI_IB_DOUBLE, OCI_INTERVAL_YM_DTY,
    OCI_INTERVAL_DS_DTY, OCI_BOOLEAN,
)

# --- StmtType (go-ora command.go:24) --------------------------------------
SELECT = 1
DML = 2
PLSQL = 3
OTHERS = 4


# ---------------------------------------------------------------------------
# SQL text handling (go-ora utils.go refineSqlText + head/tail splitting)
# ---------------------------------------------------------------------------

def refine_sql_text(text):
    """Port of go-ora ``refineSqlText`` (utils.go:59).

    Removes block comments (/* */), line comments (--), and collapses quoted
    string contents while preserving single/double quoted regions and line
    feeds.
    """
    length = len(text)
    index = 0
    in_single_quote = False
    in_double_quote = False
    skip = False
    line_comment = False
    out = []
    while index < length:
        ch = text[index]
        if ch == "\\":
            index += 1
            continue
        if ch == "/":
            if not in_double_quote and not in_single_quote:
                if index + 1 < length and text[index + 1] == "*":
                    index += 1
                    skip = True
        elif ch == "*":
            if not in_double_quote and not in_single_quote:
                if index + 1 < length and text[index + 1] == "/":
                    index += 1
                    skip = False
        elif ch == "'":
            if not skip and not line_comment and not in_double_quote:
                in_single_quote = not in_single_quote
        elif ch == '"':
            if not skip and not line_comment and not in_single_quote:
                in_double_quote = not in_double_quote
        elif ch == "-":
            if not skip:
                if index + 1 < length and text[index + 1] == "-":
                    index += 1
                    line_comment = True
        elif ch == "\n":
            if line_comment:
                line_comment = False
            else:
                out.append(ch)
        else:
            if skip or line_comment or in_single_quote or in_double_quote:
                pass
            else:
                out.append(ch)
        index += 1
    return "".join(out).strip()


def split_sql(text):
    """Separate the leading statement (head) from the remaining SQL (tail).

    The head is everything up to the first top-level ``;`` or blank line
    (mirroring the go-ora multi-statement splitter).  The tail is the rest of
    the text.  Semicolons and blank lines inside quotes / comments are ignored.

    Returns ``(head, tail)``.
    """
    length = len(text)
    index = 0
    in_single_quote = False
    in_double_quote = False
    skip = False
    line_comment = False
    head_end = None
    while index < length:
        ch = text[index]
        if ch == "\\":
            index += 1
            continue
        if ch == "/":
            if not in_double_quote and not in_single_quote:
                if index + 1 < length and text[index + 1] == "*":
                    index += 1
                    skip = True
        elif ch == "*":
            if not in_double_quote and not in_single_quote:
                if index + 1 < length and text[index + 1] == "/":
                    index += 1
                    skip = False
        elif ch == "'":
            if not skip and not line_comment and not in_double_quote:
                in_single_quote = not in_single_quote
        elif ch == '"':
            if not skip and not line_comment and not in_single_quote:
                in_double_quote = not in_double_quote
        elif ch == "-":
            if not skip:
                if index + 1 < length and text[index + 1] == "-":
                    index += 1
                    line_comment = True
        elif ch == "\n":
            if line_comment:
                line_comment = False
            elif not (skip or in_single_quote or in_double_quote):
                # blank line at top level terminates the leading statement
                if head_end is None:
                    j = index + 1
                    while j < length and text[j] in " \t\r":
                        j += 1
                    if j >= length or text[j] == "\n" or text[j] == ";":
                        head_end = index
                        break
        elif ch == ";":
            if not skip and not line_comment and not in_single_quote and not in_double_quote:
                head_end = index
                break
        index += 1
    if head_end is None:
        return text.strip(), ""
    head = text[:head_end].strip()
    tail = text[head_end + 1:].strip()
    return head, tail


def _detect_stmt_type(ucmd_text):
    """Port of go-ora NewStmt statement-type detection (command.go:326)."""
    if ucmd_text.startswith("("):
        ucmd_text = ucmd_text[1:]
    if ucmd_text.startswith("SELECT") or ucmd_text.startswith("WITH"):
        return SELECT
    if (ucmd_text.startswith("INSERT") or ucmd_text.startswith("MERGE")
            or ucmd_text.startswith("UPDATE") or ucmd_text.startswith("DELETE")):
        return DML
    if ucmd_text.startswith("DECLARE") or ucmd_text.startswith("BEGIN"):
        return PLSQL
    return OTHERS


# ---------------------------------------------------------------------------
# Command
# ---------------------------------------------------------------------------

def _make_result(summary):
    """A tiny rows-affected result object (mirrors go-ora QueryResult)."""
    class _Result:
        def __init__(self, rows):
            self.rowcount = rows
            self.rows_affected = rows
    return _Result(summary.cur_row_number if summary is not None else 0)


class Command:
    """One statement + its query/execute/fetch state over a connection."""

    def __init__(self, connection):
        self.connection = connection
        self.session = connection.session
        self.logon_mode = getattr(connection, "logon_mode", 0)

        # statement state (go-ora defaultStmt)
        self.text = ""
        self.statement_text = ""
        self.tail = ""
        self.stmt_type = OTHERS
        self.cursor_id = 0
        self.query_id = 0
        self.columns = []
        self.column_count = 0
        self.row_count = 0
        self.max_row_size = 0
        self.uac_buffer_length = 0
        self.summary = None
        self.scn_for_snapshot = [0, 0]
        self.array_bind_count = 0
        self._has_more_rows = False
        self._no_of_rows_to_fetch = getattr(
            getattr(connection, "conn_option", None), "prefetch_rows", 25) or 25
        self._has_lob = False
        self._has_long = False
        self.pars = []
        self.bulk_exec = False
        self._rows = []                 # accumulated rows from read_response (msg 7)
        self._get_data_from_server = None  # per-column flag list from the bit vector

        # client-side state (go-ora Stmt).  Underscore-prefixed so the names do
        # not collide with the ``parse()`` method.
        self._parse = True
        self._execute = True
        self._define = False
        self._re_send_par_def = False

    # ------------------------------------------------------------------
    # SQL parsing
    # ------------------------------------------------------------------
    def parse(self, query):
        """Parse ``query``: split head/tail and detect the statement type."""
        self.text = query
        head, tail = split_sql(query)
        self.statement_text = head
        self.tail = tail
        ucmd = refine_sql_text(head).upper()
        self.stmt_type = _detect_stmt_type(ucmd)
        return self

    prepare = parse  # alias used by the connection layer

    @property
    def has_return_clause(self):
        txt = refine_sql_text(self.statement_text).upper()
        return " INTO " in txt and ("RETURNING" in txt or "RETURN" in txt)

    # ------------------------------------------------------------------
    # TTC write (go-ora Stmt.basicWrite + getExeOption)
    # ------------------------------------------------------------------
    def _get_exe_option(self):
        op = 0
        if self.stmt_type == PLSQL or self.has_return_clause:
            op |= 0x40000
        if self.array_bind_count > 1:
            op |= 0x80000
        if getattr(self.connection, "auto_commit", False) \
                and (self.stmt_type == DML or self.stmt_type == PLSQL):
            op |= 0x100
        if self._parse:
            op |= 1
        if self._execute:
            op |= 0x20
        if not self._parse and not self._execute:
            op |= 0x40
        if len(self.pars) > 0 and not self._define:
            op |= 0x8
            if self.stmt_type == PLSQL or (self.has_return_clause and not self._re_send_par_def):
                op |= 0x400
        if self.stmt_type != PLSQL and not self.has_return_clause:
            op |= 0x8000
        if self._define:
            op |= 0x10
        return op

    def _encode_sql(self):
        conv = getattr(self.connection, "str_conv", None)
        if conv is None:
            return self.statement_text.encode("utf-8")
        return conv.encode(self.statement_text)

    def _basic_write(self, exe_op, parse, define):
        session = self.session
        sql_bytes = self._encode_sql()
        session.put_bytes(3, 0x5E, 0)
        session.put_uint(exe_op, 4, True, True)
        session.put_uint(self.cursor_id, 2, True, True)
        if self.cursor_id == 0:
            session.put_bytes(1)
        else:
            session.put_bytes(0)
        if parse:
            session.put_uint(len(sql_bytes), 4, True, True)
            session.put_bytes(1)
        else:
            session.put_bytes(0, 1)
        session.put_uint(13, 2, True, True)
        session.put_bytes(0, 0)
        if exe_op & 0x40 == 0 and exe_op & 0x20 != 0 and exe_op & 0x1 != 0 \
                and self.stmt_type == SELECT:
            session.put_bytes(0)
            session.put_uint(self._no_of_rows_to_fetch, 4, True, True)
        else:
            session.put_bytes(0, 0)
        # LOB handling: the core port uses the inline fetch size (0x3FFFFFFF).
        session.put_uint(0x3FFFFFFF, 4, True, True)
        if len(self.pars) > 0 and not define:
            session.put_bytes(1)
            session.put_uint(len(self.pars), 2, True, True)
        else:
            session.put_bytes(0, 0)
        session.put_bytes(0, 0, 0, 0, 0)
        if define:
            session.put_bytes(1)
            session.put_uint(len(self.columns), 2, True, True)
        else:
            session.put_bytes(0, 0)
        ttc = session.ttc_version
        if ttc >= 4:
            session.put_bytes(0, 0, 1)
        if ttc >= 5:
            session.put_bytes(0, 0, 0, 0, 0)
        if ttc >= 7:
            if self.stmt_type == DML and self.array_bind_count > 0:
                session.put_bytes(1)
                session.put_uint(self.array_bind_count, 4, True, True)
                session.put_bytes(1)
            else:
                session.put_bytes(0, 0, 0)
        if ttc >= 8:
            session.put_bytes(0, 0, 0, 0, 0)
        if ttc >= 9:
            session.put_bytes(0, 0)
        if parse:
            session.put_clr(sql_bytes)
        # al8i4 (13 longs)
        al8i4 = [0] * 13
        al8i4[0] = 1 if exe_op & 1 > 0 else 0
        if self.stmt_type in (DML, PLSQL):
            al8i4[1] = self.array_bind_count if self.array_bind_count > 0 else 1
            if self.stmt_type == DML and self.array_bind_count > 0:
                al8i4[9] = 0x4000
        elif self.stmt_type == OTHERS:
            al8i4[1] = 1
        else:  # SELECT
            al8i4[1] = 0 if parse else self._no_of_rows_to_fetch
        if len(self.scn_for_snapshot) == 2:
            al8i4[5] = self.scn_for_snapshot[0]
            al8i4[6] = self.scn_for_snapshot[1]
        if self.stmt_type == SELECT:
            al8i4[7] = 1
        if exe_op & 32 != 0:
            al8i4[9] |= 0x8000
        else:
            al8i4[9] &= ~0x8000
        for v in al8i4:
            session.put_uint(v, 4, True, True)
        if define:
            self._write_define()
        else:
            for par in self.pars:
                self._write_par(par)

    def _write_define(self):
        # TODO(stub): LOB/define column write (go-ora writeDefine).  Not needed
        # for the scalar CORE flow.
        session = self.session
        for col in self.columns:
            session.put_bytes(col.oci_type, col.oci_subtype, col.precision,
                              col.scale)
            session.put_uint(col.max_len, 4, True, True)
            session.put_uint(0, 4, True, True)
            if session.ttc_version >= 10:
                session.put_uint(col.cont_flag, 8, True, True)
            else:
                session.put_uint(col.cont_flag, 4, True, True)
            session.put_bytes(0)
            session.put_uint(0, 2, True, True)
            session.put_uint(col.charset_id, 2, True, True)
            session.put_bytes(0)
            session.put_uint(col.max_char_len or 0, 4, True, True)
            if session.ttc_version >= 8:
                session.put_uint(0, 4, True, True)

    def _write_par(self, par):
        # TODO(stub): bind parameter encoding (go-ora ParameterInfo.encodeValue
        # + writePars).  The CORE query path has no binds.
        raise NotImplementedError(
            "bind parameter encoding is not part of the CORE flow")

    def bind(self, args):
        """Register positional bind values (stub: encode is out of CORE scope)."""
        self.pars = list(args)
        return self

    def write(self, query=None):
        """Write the TTC command for ``query`` (or the previously parsed one)
        into the session output buffer and send it."""
        if query is not None:
            self.parse(query)
        session = self.session
        session.reset_buffer()
        exe_op = self._get_exe_option()
        self._basic_write(exe_op, self._parse, self._define)
        session.write()
        return self

    # ------------------------------------------------------------------
    # TTC read (go-ora defaultStmt.read essentials)
    # ------------------------------------------------------------------
    def _result_set_load(self, msg):
        session = self.session
        if msg == 6 or msg == 11:
            session.get_byte()
        column_count = session.get_int(2, True, True)
        num = session.get_int(4, True, True)
        column_count += num * 0x100
        if self.column_count == 0:
            self.column_count = column_count
        self.row_count = session.get_int(4, True, True)
        self.uac_buffer_length = session.get_int(2, True, True)
        bit_vector = session.get_dlc()  # bit vector: which columns carry data
        self._apply_bit_vector(bit_vector)
        session.get_dlc()               # trailing dlc (unused, go-ora line 64)

    def _apply_bit_vector(self, bit_vector):
        """Mark each column with ``get_data_from_server`` from the wire bit
        vector (mirrors go-ora ``ResultSet.setBitVector``).  Absence of a bit
        vector means every column carries data."""
        if self.columns is None:
            return
        if bit_vector:
            for x in range(len(bit_vector)):
                for i in range(8):
                    idx = (x * 8) + i
                    if idx < len(self.columns):
                        self.columns[idx].get_data_from_server = bool(
                            bit_vector[x] & (1 << i))
        else:
            for col in self.columns:
                col.get_data_from_server = True

    def _read_one_row(self):
        """Read one result row off the wire following a msg 7 (mirrors go-ora
        command.go ``case 7`` else-branch: only columns whose bit was set in the
        bit vector actually carry data and are read; the rest are None)."""
        conv = TypeConverter(self.connection)
        row = []
        for col in self.columns:
            if getattr(col, "get_data_from_server", True):
                row.append(conv.read(self.session, col))
            else:
                row.append(None)
        self._rows.append(row)

    def _read_column_definitions(self):
        session = self.session
        size = session.get_byte()
        session.get_bytes(size)
        self.max_row_size = session.get_int(4, True, True)
        self.column_count = session.get_int(4, True, True)
        if self.column_count > 0:
            session.get_byte()
        conv = TypeConverter(self.connection)
        self.columns = []
        for _ in range(self.column_count):
            col = conv.read_columns(session, session.ttc_version)
            if col.is_lob_type:
                self._has_lob = True
            if col.is_long_type:
                self._has_long = True
            self.columns.append(col)
        session.get_dlc()
        ttc = session.ttc_version
        if ttc >= 3:
            session.get_int(4, True, True)
            session.get_int(4, True, True)
        if ttc >= 4:
            session.get_int(4, True, True)
            session.get_int(4, True, True)
        if ttc >= 5:
            session.get_dlc()

    def _read_oall8(self):
        session = self.session
        size = session.get_int(2, True, True)
        for x in range(2):
            self.scn_for_snapshot[x] = session.get_int(4, True, True)
        for _ in range(2, size):
            session.get_int(4, True, True)
        session.get_int(2, True, True)
        size = session.get_int(2, True, True)
        for _ in range(size):
            _, val, num = session.get_key_val()
            if num == 163:
                session.time_zone = val
        if session.ttc_version >= 4:
            size = session.get_int(4, True, True)
            if size > 0:
                bty = session.get_bytes(size)
                if len(bty) >= 8:
                    self.query_id = int.from_bytes(bty[size - 8:], "little")

    def read_response(self):
        """Read the TTC response until the summary, parsing the row/column
        count, column metadata and the first row batch.

        Mirrors go-ora ``defaultStmt.read``: inline message codes 6/7/8/11/16/
        19/21 are handled here; anything else (4, 9, ...) falls through to
        ``Connection.process_ttc_response`` which builds the summary and stops
        the loop.  Each msg 7 appends one decoded row to ``self._rows``.
        Returns the parsed column list.
        """
        session = self.session
        connection = self.connection
        loop = True
        while loop:
            msg = session.get_byte()
            if msg == 4:
                session.summary = new_summary(session)
                self.summary = session.summary
                if session.summary is not None:
                    self.cursor_id = session.summary.cursor_id
                    if session.summary.ret_code == 1403:
                        self._has_more_rows = False
                loop = False
            elif msg == 8:
                self._read_oall8()
            elif msg == 6 or msg == 11:
                self._result_set_load(msg)
                if msg == 11:
                    for _ in range(self.column_count):
                        session.get_byte()
            elif msg == 7:
                # one row: read each column that the server sent
                self._read_one_row()
            elif msg == 16:
                self._read_column_definitions()
            elif msg == 19:
                # resend request handling (go-ora case 19)
                session.reset_buffer()
                session.put_bytes(19)
                session.write()
            elif msg == 21:
                # column bit vector (go-ora case 21): sets which columns
                # actually carry data in the following msg-7 data rows.
                session.get_int(2, True, True)   # noOfColumnSent
                bit_len = (self.column_count // 8) + (1 if self.column_count % 8 else 0)
                bv = bytearray()
                for _ in range(bit_len):
                    bv.append(session.get_byte())
                self._apply_bit_vector(bytes(bv))
            else:
                connection.process_ttc_response(msg)
                if msg == 9:
                    loop = False
        if session.has_error():
            raise session.get_error()
        return self.columns

    # ------------------------------------------------------------------
    # row reading (go-ora decodePrimValue essentials)
    # ------------------------------------------------------------------
    def read_data(self):
        """Read one row worth of columns off the wire using TypeConverter.

        Returns a list of decoded values, or ``None`` when no more rows are
        available (the caller detects end-of-rows via the summary / fetch)."""
        conv = TypeConverter(self.connection)
        row = []
        for col in self.columns:
            value = conv.read(self.session, col)
            row.append(value)
        self._has_more_rows = True
        return row

    def fetch_more(self):
        """TODO(stub): go-ora ``defaultStmt.fetch``/``_fetch`` for subsequent
        row batches and LOBFETCH.  The CORE flow returns the first batch."""
        raise NotImplementedError(
            "fetch_more (subsequent row batches / LOBFETCH) is out of the CORE "
            "flow scope. See command.go _fetch / queryLobPrefetch.")

    # ------------------------------------------------------------------
    # exec convenience
    # ------------------------------------------------------------------
    def exec(self, query=None):
        """Write + read the response for a DML.  Returns a result object whose
        ``.rowcount`` equals ``summary.cur_row_number`` (rows affected)."""
        if query is not None:
            self.parse(query)
        self.write()
        self.read_response()
        summary = self.session.summary
        result = _make_result(summary)
        result.summary = summary
        return result

    def query(self):
        """Run the parsed query and return a DataSet of columns + rows.

        This is the CORE select path: write, read the response (columns), then
        read the first row batch directly off the wire.
        """
        self.write()
        self.read_response()
        # Rows decoded from the wire by msg 7 handling are accumulated in
        # ``self._rows``; hand them to a ResultSet for the DB-API layer.
        data_set = ResultSet(self.columns, self._rows)
        return data_set

    def rows_affected(self):
        summary = self.session.summary
        return summary.cur_row_number if summary is not None else 0


# ---------------------------------------------------------------------------
# ResultSet — lightweight rows holder used by the DB-API layer
# ---------------------------------------------------------------------------

class ResultSet:
    """A fetched result: list of column metadata plus the row list."""

    def __init__(self, columns, rows):
        self._columns = columns
        self._rows = rows

    def columns(self):
        """Return a list of ``(name, oci_type)`` tuples."""
        return [col.to_tuple() for col in self._columns]

    def rows(self):
        return self._rows

    def column_count(self):
        return len(self._columns)

    def row_count(self):
        return len(self._rows)

    def __iter__(self):
        return iter(self._rows)


# ---------------------------------------------------------------------------
# get_db_version — port of go-ora db_version.go
# ---------------------------------------------------------------------------

def get_db_version(connection):
    """Return the database version, ported from ``db_version.go``.

    go-ora ``GetDBVersion`` writes an opcode-0x3B request and parses the
    version string off the wire.  That exact wire-level port already exists in
    ``pyora.db_version.get_db_version(session)``; the real implementation is
    delegated to it (it reads the version and returns a ``DBVersion`` object
    with ``.text``/``.number``/``.major_version`` ...).
    """
    from .db_version import get_db_version as _session_impl
    return _session_impl(connection.session)

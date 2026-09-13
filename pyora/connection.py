"""
Connection module ported from github.com/sijms/go-ora/v2 connection.go.

Ties together the network Session, protocol negotiation, O5LOGON auth,
database version retrieval, and the query/execute flow.
"""

import datetime

from .configurations import parse_config, SYSDBA, SYSOPER, SYSASM, SYSBACKUP, \
    SYSDG, SYSKM, SYSRAC, ConnectionConfig
from .network.session import Session
from .network.oracle_error import OracleError, ErrConnReset
from .network.summary_object import new_summary
from .network.marker_packet import new_marker_packet, MARKER_TYPE_RESET
from .tcp_protocol_nego import new_tcp_nego
from .data_type_nego import build_type_nego
from .auth_object import AuthObject
from .db_version import get_db_version
from .advanced_nego import AdvNego

# StringConverter is provided by the converters subpackage (ported separately).
def _strings():
    from .converters.strings import StringConverter, new_string_converter
    return StringConverter, new_string_converter

# LogonMode flags
NO_NEW_PASS = 0x1
USER_AND_PASS = 0x100
SysDba = 0x20
SysOper = 0x40
SysAsm = 0x00400000
SysBackup = 0x01000000
SysDg = 0x02000000
SysKm = 0x04000000
SysRac = 0x08000000

Closed = 0
Opened = 1


class NLSData:
    def __init__(self):
        self.language = ""
        self.territory = ""
        self.charset = ""
        self.sort = ""
        self.linguistic = ""

    def save_nls_value(self, key, value, _code):
        up = key.upper()
        if up.endswith("_LANGUAGE"):
            self.language = value
        elif up.endswith("_TERRITORY"):
            self.territory = value
        elif up.endswith("_CHARSET"):
            self.charset = value
        elif up.endswith("_SORT"):
            self.sort = value
        elif up.endswith("_LINGUISTIC"):
            self.linguistic = value


class MaxLen:
    def __init__(self):
        self.varchar = 0x7FFF
        self.nvarchar = 0x7FFF
        self.raw = 0x7FFF
        self.number = 0x16
        self.date = 0xB
        self.timestamp = 0xB


class Connection:
    def __init__(self, dsn=None, config=None):
        if dsn:
            config = parse_config(dsn)
        if config is None:
            raise ValueError("database url or configuration is required")
        self.conn_option = config
        self.state = Closed
        self.session = None
        self.tcp_nego = None
        self.data_nego = None
        self.auth_object = None
        self.db_time_zone = None
        self.db_server_time_zone = None
        self.db_server_time_zone_explicit = None
        self.logon_mode = 0
        self.auto_commit = True
        self.bad = False
        self.max_len = MaxLen()
        self.session_id = 0
        self.serial_id = 0
        self.db_version = None
        self.nls_data = NLSData()
        self.session_properties = {}
        self.cus_typ = {}
        self._str_conv = None
        self._nstr_conv = None
        self.tracer = _NilTracer()

    # ---------------- string converters ----------------
    @property
    def str_conv(self):
        if self._str_conv is None:
            StringConverter, _ = _strings()
            self._str_conv = StringConverter(self.conn_option.charset_id)
        return self._str_conv

    @property
    def nstr_conv(self):
        if self._nstr_conv is None:
            StringConverter, _ = _strings()
            self._nstr_conv = StringConverter(self.tcp_nego.servern_charset if self.tcp_nego else 0x369)
        return self._nstr_conv

    # ---------------- open / close ----------------
    def connect(self):
        cfg = self.conn_option
        mapping = {
            SYSDBA: SysDba, SYSOPER: SysOper, SYSASM: SysAsm, SYSBACKUP: SysBackup,
            SYSDG: SysDg, SYSKM: SysKm, SYSRAC: SysRac,
        }
        self.logon_mode = mapping.get(cfg.dba_privilege, 0)
        cfg.reset_server_index()
        self.session = Session(cfg)
        self.session.connect()

        # advanced negotiation (go-ora advanced_nego between connect and protocol negotiation)
        if self.session.context and \
                (self.session.context.acfl0 & 1) != 0 and \
                (self.session.context.acfl0 & 4) == 0 and \
                (self.session.context.acfl1 & 8) == 0:
            nego = AdvNego(self.session, cfg)
            nego.write()
            nego.read_full()
            nego.start_services()

        # protocol negotiation
        self.tcp_nego = new_tcp_nego(self.session)
        if self._str_conv is None:
            _, new_string_converter = _strings()
            conv = new_string_converter(self.tcp_nego.server_charset)
            if conv is None:
                raise ValueError("the server use charset with id: {} which is not supported by the driver"
                                 .format(self.tcp_nego.server_charset))
            self._str_conv = conv
        self.session.str_conv = self._str_conv
        if self._nstr_conv is None:
            _, new_string_converter = _strings()
            conv = new_string_converter(self.tcp_nego.servern_charset)
            if conv is None:
                raise ValueError("the server use ncharset with id: {} which is not supported by the driver"
                                 .format(self.tcp_nego.servern_charset))
            self._nstr_conv = conv
        self.tcp_nego.server_flags |= 2

        import os as _os
        if _os.environ.get("PYORA_DEBUG"):
            _sc = self.tcp_nego.server_compile_time_caps
            print("DBG server_compile_time_caps len={} [27]={} [7]={} hex={}".format(
                len(_sc), _sc[27] if len(_sc) > 27 else None,
                _sc[7] if len(_sc) > 7 else None, bytes(_sc).hex()),
                file=__import__("sys").stderr)
            print("DBG tcp scharset={} sflags={} schnarset={} rcap={} capslen={}".format(
                self.tcp_nego.server_charset, self.tcp_nego.server_flags,
                self.tcp_nego.servern_charset,
                bytes(self.tcp_nego.server_runtime_caps).hex(),
                len(_sc)), file=__import__("sys").stderr)

        # data type negotiation
        self.data_nego = build_type_nego(self.tcp_nego, self.session)
        self.data_nego.write(self.session)
        self.db_time_zone = self.data_nego.read(self.session)
        self.session.ttc_version = self.data_nego.compile_time_caps[7]
        self.session.use_big_scn = self.tcp_nego.server_compile_time_caps[7] >= 8
        if self.tcp_nego.server_compile_time_caps[7] < self.session.ttc_version:
            self.session.ttc_version = self.tcp_nego.server_compile_time_caps[7]
        if len(self.tcp_nego.server_runtime_caps) > 6 and self.tcp_nego.server_runtime_caps[6] & 4 == 4:
            self.max_len.varchar = 0x7FFF
            self.max_len.nvarchar = 0x7FFF
            self.max_len.raw = 0x7FFF
        else:
            self.max_len.varchar = 0xFA0
            self.max_len.nvarchar = 0xFA0
            self.max_len.raw = 0xFA0

        # IMPORTANT: go-ora performs dataTypeNegotiation write() then read().
        # We must write the DTY-nego request and then read its response. In
        # build_type_nego above we only built the object; the write() must be
        # issued before read(). Because process_ttc_response triggers
        # protocol+dataType on code 28, the negation is actually driven by the
        # auth handshake. We keep both paths consistent below.

        self.do_auth()

        self.state = Opened
        try:
            self.db_version = get_db_version(self.session)
        except Exception:
            self.db_version = None
        self.session.connected = True
        return self

    def do_auth(self):
        # step 1: O5LOGON pre-auth (only if user+password present)
        if self.conn_option.user_id and self.conn_option.password:
            self.session.reset_buffer()
            self.session.put_bytes(3, 0x76, 0, 1)
            self.session.put_uint(len(self.conn_option.user_id), 4, True, True)
            self.logon_mode |= NO_NEW_PASS
            self.session.put_uint(int(self.logon_mode), 4, True, True)
            self.session.put_bytes(1, 1, 5, 1, 1)
            self.session.put_string(self.conn_option.user_id)
            self.session.put_key_val_string("AUTH_TERMINAL", self.conn_option.host_name, 0)
            self.session.put_key_val_string("AUTH_PROGRAM_NM", self.conn_option.program_name, 0)
            self.session.put_key_val_string("AUTH_MACHINE", self.conn_option.host_name, 0)
            self.session.put_key_val_string("AUTH_PID", str(self.conn_option.pid), 0)
            self.session.put_key_val_string("AUTH_SID", self.conn_option.os_user_name, 0)
            self.session.write()
            self.auth_object = AuthObject(self.conn_option.user_id, self.conn_option.password,
                                          self.tcp_nego, self)
        else:
            class _EmptyAuth:
                def __init__(self, tg, conn):
                    self.tcp_nego = tg
                    self.use_padding = False
                    self.custom_hash = bool(tg.server_compile_time_caps[4] & 32)
                    self.e_client_sess_key = ""
                    self.e_password = ""
                    self.e_speedy_key = ""

                def write(self, conn_opt, mode, session):
                    pass
            self.auth_object = _EmptyAuth(self.tcp_nego, self)

        self.auth_object.write(self.conn_option, self.logon_mode, self.session)

        stop = False
        while not stop:
            msg = self.session.get_byte()
            if msg == 8:
                dict_len = self.session.get_int(2, True, True)
                self.session_properties = {}
                for _ in range(dict_len):
                    key, val, _ = self.session.get_key_val()
                    if key is not None:
                        _k = key.decode("utf-8", "replace")
                        if val is None:
                            self.session_properties[_k] = ""
                        else:
                            self.session_properties[_k] = val.decode("utf-8", "replace")
            else:
                self.process_ttc_response(msg)
                if msg == 4 or msg == 9:
                    stop = True
        return None

    def read(self):
        loop = True
        while loop:
            msg = self.session.get_byte()
            self.process_ttc_response(msg)
            if msg == 4 or msg == 9:
                loop = False

    def process_ttc_response(self, msg_code):
        session = self.session
        if msg_code == 4:
            session.summary = new_summary(session)
            if session.has_error():
                raise session.get_error()
        elif msg_code == 8:
            size = session.get_int(2, True, True)
            for _ in range(size):
                session.get_int(4, True, True)
            session.get_int(2, True, True)
            size = session.get_int(2, True, True)
            for _ in range(size):
                session.get_key_val()
            if session.ttc_version >= 7:
                length = session.get_int(4, True, True)
                for _ in range(length):
                    session.get_int(8, True, True)
        elif msg_code == 9:
            if session.has_eos_capability:
                temp = session.get_int(4, True, True)
                if session.summary is not None:
                    session.summary.end_of_call_status = temp
            if session.has_fsap_capability:
                if session.summary is None:
                    session.summary = _EmptySummary()
                session.summary.end_to_end_ecid_sequence = session.get_int(2, True, True)
        elif msg_code == 15:
            _read_warning(session)
        elif msg_code == 23:
            op_code = session.get_byte()
            self._get_server_network_information(op_code)
        elif msg_code == 28:
            self.tcp_nego = new_tcp_nego(session)
            self.data_nego = build_type_nego(self.tcp_nego, session)
            self.data_nego.write(session)
            self.db_time_zone = self.data_nego.read(session)
        else:
            raise IOError("TTC error: received code {} during response reading".format(msg_code))
        return None

    def _get_server_network_information(self, code):
        session = self.session
        if code == 0:
            session.get_byte()
            return None
        switch = code - 1
        if switch == 1:
            length = session.get_int(2, True, True)
            session.get_byte()
            session.get_bytes(length)
        elif switch == 3:
            session.get_int(2, True, True)
            session.get_byte()
            length = session.get_int(2, True, True)
            for _ in range(length):
                nls_key, nls_val, nls_code = session.get_key_val()
                self.nls_data.save_nls_value(
                    nls_key.decode("utf-8", "replace") if nls_key else "",
                    nls_val.decode("utf-8", "replace") if nls_val else "",
                    nls_code)
            session.get_int(4, True, True)
        return None

    def logoff(self):
        if self.session is not None:
            session = self.session
            session.reset_buffer()
            session.put_bytes(3, 9, 0)
            session.write()
            try:
                self.read()
            except Exception:
                pass

    def close(self):
        try:
            if self.session is not None:
                self.logoff()
                self.session.disconnect()
                self.session = None
        finally:
            self.state = Closed

    # ---------------- query / exec ----------------
    def get_cursor(self):
        from .command import Command
        return Command(self)

    def exec(self, query, args=None):
        """Execute a DML and return (rowcount)."""
        stmt = self.get_cursor()
        stmt.prepare(query)
        stmt.bind(args or ())
        return stmt.exec()

    def query(self, query, args=None):
        """Run a query and return a ResultSet (columns + rows)."""
        stmt = self.get_cursor()
        stmt.prepare(query)
        stmt.bind(args or ())
        return stmt.query()

    # convenience mapping for AuthObject which calls conn.process_ttc_response
    def process_ttc_response_for_auth(self, msg_code):
        return self.process_ttc_response(msg_code)


class _NilTracer:
    def print(self, *a, **k):
        pass

    def printf(self, *a, **k):
        pass

    def log_packet(self, *a, **k):
        pass


class _EmptySummary:
    def __init__(self):
        self.end_of_call_status = 0
        self.end_to_end_ecid_sequence = 0


def _read_warning(session):
    ret_code = session.get_int(2, True, True)
    length = session.get_int(2, True, True)
    flag = session.get_int(2, True, True)
    if ret_code == 0 or length == 0:
        return None
    msg = session.get_clr()
    return None

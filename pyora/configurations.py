"""
Configurations ported from github.com/sijms/go-ora/v2 configurations package.

Parses Oracle connection strings (DSN) of the form:
    oracle://user:pass@host:port/service?OPTION=value
and builds the TNS connect descriptor used in the CONNECT packet.
"""

import os
import re
import socket
from urllib.parse import urlparse, parse_qsl, unquote

DEFAULT_PORT = 1521
DEFAULT_CHARSET_ID = 0x369  # AL32UTF8

# DBAPrivilege
NONE, SYSDBA, SYSOPER, SYSASM, SYSBACKUP, SYSDG, SYSKM, SYSRAC = (
    0, 0x20, 0x40, 0x00400000, 0x01000000, 0x02000000, 0x04000000, 0x08000000,
)
# AuthType
Normal, OS, Kerberos, TCPS = 0, 1, 2, 3
# LobFetch
INLINE, STREAM = 0, 1

_CHARSET_MAP = {
    "US7ASCII": 0x1, "WE8DEC": 0x2, "WE8HP": 0x3, "US8PC437": 0x4,
    "WE8EBCDIC37": 0x5, "WE8EBCDIC500": 0x6, "WE8EBCDIC1140": 0x7,
    "WE8EBCDIC285": 0x8, "WE8EBCDIC1146": 0x9, "WE8PC850": 0xA,
    "D7DEC": 0xB, "F7DEC": 0xC, "S7DEC": 0xD, "E7DEC": 0xE,
    "SF7ASCII": 0xF, "NDK7DEC": 0x10, "I7DEC": 0x11, "NL7DEC": 0x12,
    "CH7DEC": 0x13, "YUG7ASCII": 0x14, "SF7DEC": 0x15, "TR7DEC": 0x16,
    "IW7IS960": 0x17, "IN8ISCII": 0x19, "WE8EBCDIC1148": 0x1b, "WE8PC858": 0x1c,
    "WE8ISO8859P1": 0x1f, "EE8ISO8859P2": 0x20, "SE8ISO8859P3": 0x21,
    "NEE8ISO8859P4": 0x22, "CL8ISO8859P5": 0x23, "AR8ISO8859P6": 0x24,
    "EL8ISO8859P7": 0x25, "IW8ISO8859P8": 0x26, "WE8ISO8859P9": 0x27,
    "NE8ISO8859P10": 0x28, "TH8TISASCII": 0x29, "TH8TISEBCDIC": 0x2a,
    "BN8BSCII": 0x2b, "VN8VN3": 0x2c, "VN8MSWIN1258": 0x2d, "WE8ISO8859P15": 0x2e,
    "BLT8ISO8859P13": 0x2f, "CEL8ISO8859P14": 0x30, "CL8ISOIR111": 0x31,
    "WE8NEXTSTEP": 0x32, "CL8KOI8U": 0x33, "AZ8ISO8859P9E": 0x34,
    "WE8MSWIN1252": 0xb2, "EE8MSWIN1250": 0xaa, "CL8MSWIN1251": 0xab,
    "JA16SJIS": 0x340, "KO16MSWIN949": 0x34E, "ZHS16GBK": 0x354,
    "UTF8": 0x367, "AL32UTF8": 0x369,
}


def get_charset_id(charset):
    return _CHARSET_MAP.get(charset.upper(), DEFAULT_CHARSET_ID)


def dba_privilege_from_string(s):
    mapping = {
        "SYSDBA": SYSDBA, "SYSOPER": SYSOPER, "SYSASM": SYSASM,
        "SYSBACKUP": SYSBACKUP, "SYSDG": SYSDG, "SYSKM": SYSKM, "SYSRAC": SYSRAC,
    }
    return mapping.get(s.upper(), NONE)


class ServerAddr:
    def __init__(self, addr, port=DEFAULT_PORT, protocol=None):
        self.protocol = protocol
        self.addr = addr
        self.port = port

    def is_equal(self, other):
        return self.addr.upper() == other.addr.upper() and self.port == other.port

    def network_addr(self):
        return "{}:{}".format(self.addr, self.port)


_ADDRESS_RE = re.compile(
    r"\(\s*ADDRESS\s*=\s*(\(\s*(HOST)\s*=\s*([\w\.\-\:]+)\s*\)\s*|"
    r"\(\s*(PORT)\s*=\s*([0-9]+)\s*\)\s*|\(\s*(COMMUNITY)\s*=\s*([\w.-]+)\s*\)\s*|"
    r"\(\s*(PROTOCOL)\s*=\s*(\w+)\s*\)\s*)+\s*\)", re.IGNORECASE)
_SERVICE_NAME_RE = re.compile(r"\(\s*SERVICE_NAME\s*=\s*([\w.-]+)\s*\)", re.IGNORECASE)
_SID_RE = re.compile(r"\(\s*SID\s*=\s*([\w.-]+)\s*\)", re.IGNORECASE)
_INSTANCE_NAME_RE = re.compile(r"\(\s*INSTANCE_NAME\s*=\s*([\w.-]+)\s*\)", re.IGNORECASE)


def extract_servers(conn_str):
    servers = []
    for match in _ADDRESS_RE.finditer(conn_str):
        server = ServerAddr("", DEFAULT_PORT)
        groups = match.groups()
        for x in range(1, len(groups)):
            token = groups[x]
            if token is None:
                continue
            up = token.upper()
            if up == "PROTOCOL":
                server.protocol = groups[x + 1]
                # skip value slot
            elif up == "PORT":
                server.port = int(groups[x + 1])
            elif up == "HOST":
                server.addr = groups[x + 1]
            elif up == "COMMUNITY":
                pass
        # groups layout is irregular due to alternation; recompute robustly:
        if not server.addr:
            continue
        servers.append(server)
    return servers


def _extract_servers_robust(conn_str):
    """Robust ADDRESS extractor tolerant of the alternation-group layout."""
    servers = []
    for match in _ADDRESS_RE.finditer(conn_str):
        s = ServerAddr("", DEFAULT_PORT)
        text = match.group(0)
        hm = re.search(r"\(\s*HOST\s*=\s*([\w\.\-\:]+)\s*\)", text, re.IGNORECASE)
        pm = re.search(r"\(\s*PORT\s*=\s*([0-9]+)\s*\)", text, re.IGNORECASE)
        prm = re.search(r"\(\s*PROTOCOL\s*=\s*(\w+)\s*\)", text, re.IGNORECASE)
        if hm:
            s.addr = hm.group(1)
        if pm:
            s.port = int(pm.group(1))
        if prm:
            s.protocol = prm.group(1)
        if s.addr:
            servers.append(s)
    return servers


class ConnectionConfig:
    def __init__(self):
        # ClientInfo
        self.program_path = ""
        self.program_name = ""
        self.os_user_name = ""
        self.os_password = ""
        self.host_name = ""
        self.domain_name = ""
        self.driver_name = "OracleClientGo"
        self.pid = os.getpid()
        self.use_kerberos = False
        self.language = "AMERICAN"
        self.territory = "AMERICA"
        self.charset_id = DEFAULT_CHARSET_ID
        self.cid = ""
        # DatabaseInfo
        self.user_id = ""
        self.password = ""
        self.servers = []
        self.server_index = 0
        self.sid = ""
        self.proxy_client_name = ""
        self.service_name = ""
        self.instance_name = ""
        self.db_name = ""
        self.dba_privilege = NONE
        self.auth_type = Normal
        self.conn_str = ""
        self.location = ""
        # SessionInfo
        self.ssl_version = ""
        self.connect_timeout = 60.0
        self.timeout = 0.0
        self.enable_oob = False
        self.unix_address = ""
        self.transport_data_unit_size = 0x200000
        self.session_data_unit_size = 0x200000
        self.protocol = "tcp"
        self.ssl = False
        self.ssl_verify = True
        self.tls_config = None
        self.dialer = None
        # AdvNegoServiceInfo
        self.auth_service = []
        self.enc_service_level = 0
        self.int_service_level = 0
        self.kerberos = None
        # others
        self.trace_file_path = ""
        self.trace_dir = ""
        self.prefetch_rows = 25
        self.lob = INLINE

    # ---- session info helpers ----
    def update_ssl(self, server=None):
        if server is not None:
            if (server.protocol or "").lower() == "tcps":
                self.ssl = True
                return
            if (server.protocol or "").lower() == "tcp":
                self.ssl = False
                return
        proto = self.protocol.lower()
        if proto == "tcp":
            self.ssl = False
        elif proto == "tcps":
            self.ssl = True
        else:
            raise ValueError("unknown or missing protocol: {}".format(self.protocol))

    # ---- database info helpers ----
    def reset_server_index(self):
        self.server_index = 0

    def get_active_server(self, jump=False):
        if jump:
            self.server_index += 1
        if self.server_index >= len(self.servers):
            return None
        return self.servers[self.server_index]

    def add_server(self, server):
        for s in self.servers:
            if s.is_equal(server):
                return
        self.servers.append(server)

    def update_database_info(self, conn_str):
        conn_str = conn_str.replace("\r", "").replace("\n", "")
        self.servers = _extract_servers_robust(conn_str)
        if not self.servers:
            raise ValueError("no address passed in connection string")
        self.conn_str = conn_str
        m = _SERVICE_NAME_RE.search(conn_str)
        if m:
            self.service_name = m.group(1)
        m = _SID_RE.search(conn_str)
        if m:
            self.sid = m.group(1)
        m = _INSTANCE_NAME_RE.search(conn_str)
        if m:
            self.instance_name = m.group(1)
        return None

    def update_database_info_for_redirect(self, redirect_addr, reconnect_data):
        redirect_addr = redirect_addr.replace("\r", "").replace("\n", "")
        reconnect_data = reconnect_data.replace("\r", "").replace("\n", "")
        self.servers = _extract_servers_robust(redirect_addr)
        if not self.servers:
            raise ValueError("no address passed in connection string")
        m = _SERVICE_NAME_RE.search(reconnect_data)
        if m:
            self.service_name = m.group(1)
        m = _SID_RE.search(reconnect_data)
        if m:
            self.sid = m.group(1)
        m = _INSTANCE_NAME_RE.search(reconnect_data)
        if m:
            self.instance_name = m.group(1)
        self.conn_str = ""
        return None

    # ---- ConnectionData / connect descriptor ----
    def connection_data(self):
        if self.conn_str:
            return self.conn_str
        host = self.get_active_server(False)
        if host is None:
            host = ServerAddr("127.0.0.1", DEFAULT_PORT)
        protocol = self.protocol
        if host.protocol:
            protocol = host.protocol
        f_cid = "(CID=(PROGRAM={0})(HOST={1})(USER={2}))".format(
            self.program_path, self.host_name, self.os_user_name)
        if self.cid:
            f_cid = self.cid
        if self.unix_address:
            address = "(ADDRESS=(PROTOCOL=IPC)(KEY=EXTPROC1))"
        else:
            address = "(ADDRESS=(PROTOCOL={0})(HOST={1})(PORT={2}))".format(
                protocol, host.addr, host.port)
        result = "(CONNECT_DATA="
        if self.sid:
            result += "(SID={})".format(self.sid)
        else:
            result += "(SERVICE_NAME={})".format(self.service_name)
        if self.instance_name:
            result += "(INSTANCE_NAME={})".format(self.instance_name)
        result += f_cid
        return "(DESCRIPTION=" + address + result + "))"

    def validate(self):
        if not self.sid and not self.service_name:
            raise ValueError("empty SID and service name")
        if self.auth_type == Kerberos:
            self.auth_service.append("KERBEROS5")
        if self.auth_type == TCPS:
            self.auth_service.append("TCPS")
        if (not self.user_id or not self.password) and self.auth_type == Normal:
            self.auth_type = OS
        if self.auth_type == OS and os.name == "nt":
            self.auth_service.append("NTS")
        if self.ssl:
            self.protocol = "tcps"
        self.host_name = socket.gethostname()
        self.program_path = os.path.basename(sys_argv0()) if os.path.basename(sys_argv0()) else "python"
        if not self.program_name:
            self.program_name = os.path.basename(sys_argv0()) or "python"
        self.driver_name = "OracleClientGo"
        return None


def sys_argv0():
    import sys
    return sys.argv[0] if sys.argv else ""


def parse_config(dsn):
    u = urlparse(dsn)
    if u.scheme and u.scheme.lower() not in ("oracle", "oracle+tcp", "oci"):
        # Allow bare host[:port]/service without scheme too.
        pass
    q = parse_qsl(u.query)
    config = ConnectionConfig()
    config.prefetch_rows = 25
    config.connect_timeout = 60.0
    config.timeout = 0.0
    config.transport_data_unit_size = 0x200000
    config.session_data_unit_size = 0x200000
    config.protocol = "tcp"
    config.ssl = False
    config.ssl_verify = True
    config.servers = []
    config.territory = "AMERICA"
    config.language = "AMERICAN"

    config.user_id = u.username or ""
    config.password = u.password or ""
    # urlparse does NOT unquote netloc userinfo (%40 -> @, %21 -> !, etc).
    # go-ora URL-decodes the DSN userid/password, so must we.
    config.user_id = unquote(config.user_id)
    config.password = unquote(config.password)
    if config.user_id.upper() == "SYS":
        config.dba_privilege = SYSDBA

    host = u.hostname
    port = u.port if u.port else DEFAULT_PORT
    if host:
        config.servers.append(ServerAddr(host, port))
    config.service_name = u.path.lstrip("/")

    for key, val in q:
        up = key.upper()
        if up == "CID":
            config.cid = val
        elif up == "CONNSTR":
            config.update_database_info(val)
        elif up == "SERVER":
            for srv in [x.strip() for x in val.split(",")] if "," in val else [val]:
                srv = srv.strip()
                if not srv:
                    continue
                if ":" in srv:
                    h, _, p = srv.rpartition(":")
                    sp = int(p) if p.isdigit() else DEFAULT_PORT
                else:
                    h, sp = srv, DEFAULT_PORT
                config.servers.append(ServerAddr(h, sp))
        elif up == "SERVICE NAME":
            config.service_name = val
        elif up == "SID":
            config.sid = val
        elif up == "INSTANCE NAME":
            config.instance_name = val
        elif up == "AUTH TYPE":
            v = val.upper()
            if v == "OS":
                config.auth_type = OS
            elif v == "KERBEROS":
                config.auth_type = Kerberos
            elif v == "TCPS":
                config.auth_type = TCPS
            else:
                config.auth_type = Normal
        elif up == "OS USER":
            config.os_user_name = val
        elif up in ("OS PASS", "OS PASSWORD"):
            config.os_password = val
        elif up == "OS HASH":
            config.os_password = val
        elif up == "DOMAIN":
            config.domain_name = val
        elif up == "AUTH SERV":
            for tv in [x.strip().upper() for x in val.split(",")]:
                if tv and not any(a.upper() == tv for a in config.auth_service):
                    config.auth_service.append(tv)
        elif up == "ENCRYPTION":
            level = {"ACCEPTED": 0, "REJECTED": 1, "REQUESTED": 2, "REQUIRED": 3}
            if val.upper() not in level:
                raise ValueError("unknown encryption service level: {}".format(val))
            config.enc_service_level = level[val.upper()]
        elif up == "DATA INTEGRITY":
            level = {"ACCEPTED": 0, "REJECTED": 1, "REQUESTED": 2, "REQUIRED": 3}
            if val.upper() not in level:
                raise ValueError("unknown data integrity service level: {}".format(val))
            config.int_service_level = level[val.upper()]
        elif up == "SSL":
            config.ssl = val.upper() in ("TRUE", "ENABLE", "ENABLED")
        elif up == "SSL VERIFY":
            config.ssl_verify = val.upper() in ("TRUE", "ENABLE", "ENABLED")
        elif up == "DBA PRIVILEGE":
            config.dba_privilege = dba_privilege_from_string(val)
        elif up in ("TIMEOUT", "READ TIMEOUT", "SOCKET TIMEOUT"):
            config.timeout = float(val)
        elif up in ("CONNECT TIMEOUT", "CONNECTION TIMEOUT"):
            config.connect_timeout = float(val)
        elif up in ("USE_OOB", "ENABLE_OOB", "ENABLE URGENT DATA TRANSPORT"):
            config.enable_oob = True
        elif up == "PREFETCH_ROWS":
            try:
                config.prefetch_rows = int(val)
            except ValueError:
                config.prefetch_rows = 25
        elif up == "UNIX SOCKET":
            config.unix_address = val
        elif up == "PROXY CLIENT NAME":
            config.proxy_client_name = val
        elif up == "LOB FETCH":
            tv = val.upper()
            if tv in ("PRE", "INLINE"):
                config.lob = INLINE
            elif tv in ("POST", "STREAM"):
                config.lob = STREAM
            else:
                raise ValueError("LOB FETCH value should be either INLINE/PRE (default) or STREAM/POST")
        elif up == "LANGUAGE":
            config.language = val
        elif up == "TERRITORY":
            config.territory = val
        elif up in ("CHARSET", "CLIENT CHARSET"):
            config.charset_id = get_charset_id(val)
        elif up == "PROGRAM":
            config.program_name = val
        elif up == "SERVER LOCATION":
            config.location = val
        else:
            raise ValueError("unknown URL option: {}".format(key))

    if not config.servers:
        raise ValueError("empty connection servers")
    config.validate()
    return config

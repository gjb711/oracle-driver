"""
RefusePacket and RedirectPacket ported from
github.com/sijms/go-ora/v2 network/refuse_packet.go and redirect_packet.go
"""

import re
import struct

from .packets import Packet, REFUSE, REDIRECT
from .oracle_error import OracleError, new_oracle_error

_ERR_EXTRACT_RE = re.compile(r"\(\s*ERR\s*=\s*([0-9]+)\s*\)", re.IGNORECASE)
_ERROR_EXTRACT_RE = re.compile(r"\(\s*ERROR\s*=([A-Z0-9=()]+)", re.IGNORECASE)
_CODE_EXTRACT_RE = re.compile(r"CODE\s*=\s*([0-9]+)", re.IGNORECASE)


class RefusePacket(Packet):
    def __init__(self):
        super().__init__(packet_type=REFUSE, flag=0, data_offset=12)
        self.err = None
        self.system_reason = 0
        self.user_reason = 0
        self.message = ""

    def extract_err_code(self):
        self.err = new_oracle_error(12564)
        if not self.message:
            return
        msg = self.message.upper()
        m = _ERR_EXTRACT_RE.search(msg)
        if m:
            try:
                self.err = new_oracle_error(int(m.group(1)))
                return
            except ValueError:
                pass
        m2 = _ERROR_EXTRACT_RE.search(msg)
        if not m2:
            return
        m3 = _CODE_EXTRACT_RE.search(m2.group(1))
        if m3:
            try:
                self.err = new_oracle_error(int(m3.group(1)))
                return
            except ValueError:
                pass


def new_refuse_packet_from_data(packet_data):
    if len(packet_data) < 12:
        return None
    data_len = struct.unpack(">H", packet_data[10:12])[0]
    message = ""
    if len(packet_data) >= 12 + data_len:
        message = packet_data[12:12 + data_len].decode("utf-8", "replace")
    pck = RefusePacket()
    pck.length = struct.unpack(">H", packet_data[0:2])[0]
    pck.packet_type = packet_data[4]
    pck.system_reason = packet_data[9]
    pck.user_reason = packet_data[8]
    pck.message = message
    return pck


class RedirectPacket(Packet):
    def __init__(self):
        super().__init__(packet_type=REDIRECT, flag=0, data_offset=10)
        self.redirect_addr = ""
        self.reconnect_data = ""


def new_redirect_packet_from_data(packet_data):
    if len(packet_data) < 10:
        return None
    pck = RedirectPacket()
    pck.length = struct.unpack(">H", packet_data[0:2])[0]
    pck.packet_type = packet_data[4]
    pck.flag = packet_data[5]
    return pck

"""
AcceptPacket ported from github.com/sijms/go-ora/v2 network/accept_packet.go
"""

import struct

from .packets import Packet, ACCEPT
from .session_ctx import SessionContext


class AcceptPacket(Packet):
    def __init__(self):
        super().__init__(packet_type=ACCEPT, flag=0)
        self.buffer = b""


def new_accept_packet_from_data(packet_data, config):
    if len(packet_data) < 32:
        return None
    recon_add_start = struct.unpack(">H", packet_data[28:30])[0]
    recon_add_len = struct.unpack(">H", packet_data[30:32])[0]
    recon_add = ""
    if recon_add_start != 0 and recon_add_len != 0 and len(packet_data) > (recon_add_start + recon_add_len):
        recon_add = packet_data[recon_add_start:(recon_add_start + recon_add_len)].decode("utf-8", "replace")

    ctx = SessionContext(config)
    ctx.version = struct.unpack(">H", packet_data[8:10])[0]
    ctx.negotiated_options = struct.unpack(">H", packet_data[10:12])[0]
    ctx.histone = struct.unpack(">H", packet_data[16:18])[0]
    ctx.recon_addr = recon_add
    ctx.acfl0 = packet_data[22]
    ctx.acfl1 = packet_data[23]
    ctx.session_data_unit = struct.unpack(">H", packet_data[12:14])[0]
    ctx.transport_data_unit = struct.unpack(">H", packet_data[14:16])[0]

    pck = AcceptPacket()
    pck.session_ctx = ctx
    pck.data_offset = struct.unpack(">H", packet_data[20:22])[0]
    pck.length = struct.unpack(">H", packet_data[0:2])[0]
    pck.packet_type = packet_data[4]
    pck.flag = packet_data[5]
    pck.buffer = packet_data[pck.data_offset:]
    if ctx.version >= 315:
        ctx.session_data_unit = struct.unpack(">I", packet_data[32:36])[0]
        ctx.transport_data_unit = struct.unpack(">I", packet_data[36:40])[0]
    if (pck.flag & 1) > 0:
        pck.length -= 16
        ctx.sid = packet_data[pck.length:]
    if ctx.transport_data_unit < ctx.session_data_unit:
        ctx.session_data_unit = ctx.transport_data_unit
    if struct.unpack(">H", packet_data[18:20])[0] != len(pck.buffer):
        return None
    return pck

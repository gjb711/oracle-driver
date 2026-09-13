"""
ConnectPacket ported from github.com/sijms/go-ora/v2 network/connect_packet.go
"""

import struct

from .packets import Packet, CONNECT


class ConnectPacket(Packet):
    def __init__(self, session_ctx=None, buffer=b""):
        super().__init__(session_ctx=session_ctx, packet_type=CONNECT, flag=0, data_offset=70)
        self.buffer = buffer
        connect_len = len(buffer)
        if connect_len > 230:
            connect_len = 0
        self.length = connect_len + 70

    def bytes(self):
        output = bytearray(super().bytes())
        ctx = self.session_ctx
        output[8:10] = struct.pack(">H", ctx.version)
        output[10:12] = struct.pack(">H", ctx.lo_version)
        output[12:14] = struct.pack(">H", ctx.options)
        num = min(ctx.session_data_unit, 0xFFFF)
        output[14:16] = struct.pack(">H", num)
        output[58:62] = struct.pack(">I", ctx.session_data_unit)
        num = min(ctx.transport_data_unit, 0xFFFF)
        output[16:18] = struct.pack(">H", num)
        output[62:66] = struct.pack(">I", ctx.transport_data_unit)
        output[66:70] = struct.pack(">I", 0)
        output[18] = 79
        output[19] = 152
        output[22:24] = struct.pack(">H", ctx.our_one)
        output[24:26] = struct.pack(">H", len(self.buffer))
        output[26:28] = struct.pack(">H", self.data_offset)
        output[32] = ctx.acfl0
        output[33] = ctx.acfl1
        if len(self.buffer) <= 230:
            output.extend(self.buffer)
        return bytes(output)


def new_connect_packet(session_ctx):
    connect_data = session_ctx.conn_config.connection_data().encode("utf-8")
    session_ctx.histone = 1
    session_ctx.acfl0 = 1
    session_ctx.acfl1 = 1
    pck = ConnectPacket(session_ctx=session_ctx, buffer=connect_data)
    if session_ctx.is_redirect:
        pck.flag = 4
    return pck

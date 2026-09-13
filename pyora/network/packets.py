"""
Packet types and base Packet class ported from
github.com/sijms/go-ora/v2 network/packets.go
"""

import struct

# PacketType constants
CONNECT = 1
ACCEPT = 2
ACK = 3
REFUSE = 4
REDIRECT = 5
DATA = 6
NULL = 7
ABORT = 9
RESEND = 11
MARKER = 12
ATTN = 13
CTRL = 14
HIGHEST = 19


class Packet:
    def __init__(self, session_ctx=None, packet_type=0, flag=0, data_offset=0, length=0):
        self.data_offset = data_offset
        self.length = length
        self.packet_type = packet_type
        self.flag = flag
        self.session_ctx = session_ctx

    def bytes(self):
        output = bytearray(8)
        # header area beyond 8 bytes for data_offset
        if self.data_offset > 8:
            output.extend(b"\x00" * (self.data_offset - 8))
        if self.session_ctx is not None and self.session_ctx.handshake_complete and self.session_ctx.version >= 315:
            output[0:4] = struct.pack(">I", self.length)
        else:
            output[0:2] = struct.pack(">H", self.length)
        output[4] = self.packet_type
        output[5] = self.flag
        return output

    def get_packet_type(self):
        return self.packet_type

    def get_flag(self):
        return self.flag

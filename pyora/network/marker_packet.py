"""
MarkerPacket ported from github.com/sijms/go-ora/v2 network/marker_packet.go
"""

import struct

from .packets import Packet, MARKER

MARKER_TYPE_RESET = 2
MARKER_TYPE_INTERRUPT = 3


class MarkerPacket(Packet):
    def __init__(self, session_ctx=None, marker_type=0):
        super().__init__(session_ctx=session_ctx, packet_type=MARKER, flag=0x20, data_offset=0, length=0xB)
        self.marker_type = marker_type

    def bytes(self):
        if self.session_ctx is not None and self.session_ctx.handshake_complete and self.session_ctx.version >= 315:
            return bytes([0, 0x0, 0, 0xB, 0xC, 0, 0, 0, 1, 0, self.marker_type])
        return bytes([0, 0xB, 0, 0, 0xC, 0, 0, 0, 1, 0, self.marker_type])


def new_marker_packet(marker_type, session_ctx):
    return MarkerPacket(session_ctx=session_ctx, marker_type=marker_type)


def new_marker_packet_from_data(packet_data, session_ctx):
    if len(packet_data) != 0xB:
        return None
    pck = MarkerPacket(session_ctx=session_ctx, marker_type=packet_data[10])
    pck.packet_type = packet_data[4]
    pck.flag = packet_data[5]
    if session_ctx.handshake_complete and session_ctx.version >= 315:
        pck.length = struct.unpack(">I", packet_data[0:4])[0]
    else:
        pck.length = struct.unpack(">H", packet_data[0:2])[0]
    if pck.packet_type != MARKER:
        return None
    return pck

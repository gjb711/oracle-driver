"""
MarkerPacket ported from github.com/sijms/go-ora/v2 network/marker_packet.go

Wire layout of the 11-byte marker packet (after the 8-byte header)::

    [0] [1] [2] [3] [4]=0x0C [5] [6] [7] [8]=markerType [9]=0 [10]=markerData

``markerType`` lives at index 8 and ``markerData`` at index 10 -- they are two
distinct fields.  The client always *answers* with ``markerType = 1`` and a
``markerData`` chosen by the caller (go-ora ``newMarkerPacket(markerData, ...)``);
the server uses ``markerData == 2`` to request a connection reset.
"""

import struct

from .packets import Packet, MARKER

# markerData value the client echoes when the server requested a reset
MARKER_TYPE_RESET = 2
MARKER_TYPE_INTERRUPT = 3

# markerType values used on the wire
MARKER_TYPE_BREAK = 0
MARKER_TYPE_DATA = 1


class MarkerPacket(Packet):
    def __init__(self, session_ctx=None, marker_type=MARKER_TYPE_DATA, marker_data=0):
        super().__init__(session_ctx=session_ctx, packet_type=MARKER, flag=0x20, data_offset=0, length=0xB)
        self.marker_type = marker_type
        self.marker_data = marker_data

    def bytes(self):
        if self.session_ctx is not None and self.session_ctx.handshake_complete and self.session_ctx.version >= 315:
            return bytes([0, 0x0, 0, 0xB, 0xC, 0, 0, 0, self.marker_type, 0, self.marker_data])
        return bytes([0, 0xB, 0, 0, 0xC, 0, 0, 0, self.marker_type, 0, self.marker_data])


def new_marker_packet(marker_data, session_ctx):
    """go-ora ``newMarkerPacket(markerData, sessionCtx)``: markerType is fixed to 1."""
    return MarkerPacket(session_ctx=session_ctx, marker_type=MARKER_TYPE_DATA,
                        marker_data=marker_data)


def new_marker_packet_from_data(packet_data, session_ctx):
    if len(packet_data) != 0xB:
        return None
    pck = MarkerPacket(session_ctx=session_ctx,
                       marker_type=packet_data[8],
                       marker_data=packet_data[10])
    pck.packet_type = packet_data[4]
    pck.flag = packet_data[5]
    if session_ctx.handshake_complete and session_ctx.version >= 315:
        pck.length = struct.unpack(">I", packet_data[0:4])[0]
    else:
        pck.length = struct.unpack(">H", packet_data[0:2])[0]
    if pck.packet_type != MARKER:
        return None
    return pck

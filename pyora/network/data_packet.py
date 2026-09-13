"""
DataPacket ported from github.com/sijms/go-ora/v2 network/data_packet.go
"""

import struct

from .packets import Packet, DATA


class DataPacket(Packet):
    def __init__(self, session_ctx=None, data_flag=0, buffer=b""):
        super().__init__(session_ctx=session_ctx, packet_type=DATA, flag=0, data_offset=0xA)
        self.data_flag = data_flag
        self.buffer = buffer
        self.length = len(buffer) + 0xA

    def bytes(self):
        output = bytearray(super().bytes())
        output[8:10] = struct.pack(">H", self.data_flag)
        if self.buffer:
            output.extend(self.buffer)
        return bytes(output)


def new_data_packet(initial_data, session_ctx, tracer=None):
    data = bytearray(initial_data or b"")
    if session_ctx.advanced_service.hash_algo is not None:
        hash_data = session_ctx.advanced_service.hash_algo.compute(bytes(data))
        data.extend(hash_data)
    if session_ctx.advanced_service.crypt_algo is not None:
        data = bytearray(session_ctx.advanced_service.crypt_algo.encrypt(bytes(data)))
    if (session_ctx.advanced_service.hash_algo is not None
            or session_ctx.advanced_service.crypt_algo is not None):
        data.append(0)  # folding key
    return DataPacket(session_ctx=session_ctx, data_flag=0, buffer=bytes(data))


def new_data_packet_from_data(packet_data, session_ctx, tracer=None):
    if len(packet_data) < 0xA or data_packet_type(packet_data) != DATA:
        raise ValueError("not data packet")
    pck = DataPacket(session_ctx=session_ctx, data_flag=0, buffer=packet_data[10:])
    pck.packet_type = data_packet_type(packet_data)
    pck.flag = packet_data[5]
    pck.data_flag = struct.unpack(">H", packet_data[8:10])[0]
    if session_ctx.handshake_complete and session_ctx.version >= 315:
        pck.length = struct.unpack(">I", packet_data[0:4])[0]
    else:
        pck.length = struct.unpack(">H", packet_data[0:2])[0]
    buf = pck.buffer
    if len(buf) > 1:
        if session_ctx.advanced_service.crypt_algo is not None or session_ctx.advanced_service.hash_algo is not None:
            buf = buf[:len(buf) - 1]
        if session_ctx.advanced_service.crypt_algo is not None:
            buf = session_ctx.advanced_service.crypt_algo.decrypt(buf)
        if session_ctx.advanced_service.hash_algo is not None:
            buf = session_ctx.advanced_service.hash_algo.validate(buf)
    pck.buffer = buf
    return pck


def data_packet_type(packet_data):
    return packet_data[4]

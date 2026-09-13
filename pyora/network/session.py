"""
Session: TTC network session and byte-level (de)serialization.

Ported from github.com/sijms/go-ora/v2 network/session.go.

The Session owns the socket, the packet framing, and all the TTC wire
primitives used by higher layers: PutUint/PutInt (with variable-length
"compressed" encoding), PutClr/GetClr (character-length representation),
KeyVal, and the packet read/write loop.
"""

import socket
import struct

from .packets import (
    CONNECT, ACCEPT, REFUSE, REDIRECT, DATA, RESEND, MARKER,
)
from .data_packet import new_data_packet, new_data_packet_from_data
from .connect_packet import new_connect_packet
from .accept_packet import new_accept_packet_from_data
from .refuse_packet import new_refuse_packet_from_data
from .marker_packet import (
    new_marker_packet, new_marker_packet_from_data, MARKER_TYPE_RESET,
)
from .session_ctx import SessionContext, new_session_context
from .oracle_error import OracleError, new_oracle_error, ErrConnReset

READ_BUFFER_SIZE = 0x4000


class Session:
    def __init__(self, config=None, tracer=None):
        self.conn = None          # socket
        self.sockfile = None      # buffered reader stream
        self.remaining_bytes = 0
        self.last_packet = bytearray()
        self.context = new_session_context(config) if config is not None else SessionContext()
        self.send_pcks = []
        self.in_buffer = bytearray()
        self.out_buffer = bytearray()
        self.time_zone = None
        self.ttc_version = 3
        self.has_eos_capability = False
        self.has_fsap_capability = False
        self.summary = None
        self.use_big_clr_chunks = False
        self.use_big_scn = False
        self.clr_chunk_size = 0x40
        self.break_conn = False
        self.connected = False
        self.str_conv = None
        self.tracer = tracer or _NilTracer()

    # ------------------------------------------------------------------
    # networking
    # ------------------------------------------------------------------
    def _sock_read(self, size):
        """Read exactly size bytes from the buffered reader."""
        if self.sockfile is None:
            raise OSError("closed connection")
        buf = bytearray()
        while len(buf) < size:
            chunk = self.sockfile.read(size - len(buf))
            if not chunk:
                raise OSError("connection reset by peer")
            buf.extend(chunk)
        return bytes(buf)

    def _sock_write(self, data):
        import os as _os
        if _os.environ.get("PYORA_DEBUG"):
            _type = data[4] if len(data) > 4 else 0
            print("DBG SEND type={} len={} hex={}".format(_type, len(data),
                  bytes(data).hex()), file=__import__("sys").stderr)
        if self.conn is None:
            raise OSError("attempt to write on closed connection")
        self.conn.sendall(data)

    def read_all(self, size):
        index = 0
        data = self._sock_read(size)
        self.last_packet.extend(data)
        return None

    def read_packet_data(self):
        if self.remaining_bytes > 0:
            if len(self.last_packet) < 8:
                pass  # break occurred inside header
            self.read_all(self.remaining_bytes)
            self.remaining_bytes = 0
            return None
        del self.last_packet[:]
        self.read_all(8)
        head = bytes(self.last_packet[:8])
        import os as _os
        if _os.environ.get("PYORA_DEBUG"):
            print("DBG header hex=", head.hex(), file=__import__("sys").stderr)
        if self.context.handshake_complete and self.context.version >= 315:
            length = struct.unpack(">I", head[0:4])[0]
        else:
            length = struct.unpack(">H", head[0:2])[0]
        if _os.environ.get("PYORA_DEBUG"):
            print("DBG length field=", length, file=__import__("sys").stderr)
        length -= 8
        self.read_all(length)
        if _os.environ.get("PYORA_DEBUG"):
            print("DBG full raw len={} hex={}".format(len(self.last_packet),
                  bytes(self.last_packet).hex()), file=__import__("sys").stderr)
        return None

    def read_packet(self):
        self.read_packet_data()
        packet_data = bytes(self.last_packet)
        pck_type = packet_data[4]
        flag = packet_data[5]

        if pck_type == RESEND:
            for pck in self.send_pcks:
                self._sock_write(pck.bytes())
            return self.read_packet()

        if pck_type == ACCEPT:
            return new_accept_packet_from_data(packet_data, self.context.conn_config)

        if pck_type == REFUSE:
            return new_refuse_packet_from_data(packet_data)

        if pck_type == REDIRECT:
            from .refuse_packet import RedirectPacket, new_redirect_packet_from_data
            pck = new_redirect_packet_from_data(packet_data)
            data_len = struct.unpack(">H", packet_data[8:10])[0]
            if pck.length <= pck.data_offset:
                self.read_packet_data()
                packet_data = bytes(self.last_packet)
                data_pck = new_data_packet_from_data(packet_data, self.context)
                data = data_pck.buffer
            else:
                data = bytes(packet_data[10:10 + data_len])
            try:
                data = data.decode("utf-8", "replace")
            except Exception:
                pass
            length = data.find("\x00")
            if pck.flag & 2 != 0 and length > 0:
                pck.redirect_addr = data[:length]
                pck.reconnect_data = data[length:]
            else:
                pck.redirect_addr = data
            return pck

        if pck_type == DATA:
            data_pck = new_data_packet_from_data(packet_data, self.context)
            if data_pck is not None:
                if data_pck.data_flag == 0x40:
                    self.disconnect()
                    raise ErrConnReset()
                self.in_buffer.extend(data_pck.buffer)
            return None

        if pck_type == MARKER:
            return new_marker_packet_from_data(packet_data, self.context)

        raise ValueError("unsupported packet type: {}".format(pck_type))

    def connect(self):
        config = self.context.conn_config
        self.reset_buffer()
        self.disconnect()
        connected = False
        err = None
        host = None
        while True:
            host = config.get_active_server(False)
            if host is None:
                if err is not None:
                    raise err
                raise OSError("no available servers to connect to")
            addr = host.network_addr()
            try:
                if config.unix_address:
                    self.conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    self.conn.settimeout(config.connect_timeout if config.connect_timeout else None)
                    self.conn.connect(config.unix_address)
                else:
                    self.conn = socket.create_connection((host.addr, host.port),
                                                         timeout=config.connect_timeout if config.connect_timeout else None)
                connected = True
                break
            except OSError as e:
                err = e
                host = config.get_active_server(True)
                if host is None:
                    break
        if not connected:
            raise err
        self.sockfile = self.conn.makefile("rb", buffering=READ_BUFFER_SIZE)
        connect_packet = new_connect_packet(self.context)
        self.write_packet(connect_packet)
        if connect_packet.length == connect_packet.data_offset:
            self.put_bytes(connect_packet.buffer)
            self.write()
        pck = self.read_packet()
        if isinstance(pck, accept_packet_type()):
            self.context = pck.session_ctx
            self.context.handshake_complete = True
            return None
        if isinstance(pck, redirect_type()):
            self.context.conn_config.update_database_info_for_redirect(
                pck.redirect_addr, pck.reconnect_data)
            self.context.conn_config.reset_server_index()
            self.context.is_redirect = True
            return self.connect()
        if isinstance(pck, refuse_type()):
            pck.extract_err_code()
            host = self.context.conn_config.get_active_server(True)
            if host is None:
                self.disconnect()
                err = pck.err
                if err is None:
                    err = OracleError(12564, pck.message)
                raise err
            return self.connect()
        raise OSError("connection refused by the server due to unknown reason")

    def disconnect(self):
        if self.conn is not None:
            try:
                self.conn.close()
            except OSError:
                pass
            self.conn = None
        if self.sockfile is not None:
            self.sockfile = None

    # ------------------------------------------------------------------
    # packet write helpers
    # ------------------------------------------------------------------
    def write_packet(self, pck):
        self.send_pcks.append(pck)
        data = pck.bytes()
        self._sock_write(data)

    def write(self):
        """Send the output buffer, splitting into data packets as needed."""
        output = bytes(self.out_buffer)
        size = len(output)
        if size == 0:
            return self.write_packet(new_data_packet(None, self.context))
        segment_len = int(self.context.session_data_unit - 64)
        offset = 0
        if size > segment_len:
            while size > segment_len:
                segment = output[offset:offset + segment_len]
                pck = new_data_packet(segment, self.context)
                self.write_packet(pck)
                size -= segment_len
                offset += segment_len
        if size != 0:
            pck = new_data_packet(output[offset:], self.context)
            self.write_packet(pck)
        del self.out_buffer[:]
        return None

    def reset_write(self):
        self.send_pcks = []
        del self.out_buffer[:]

    def reset_read(self):
        del self.in_buffer[:]

    def reset_buffer(self):
        self.summary = None
        self.reset_write()
        self.reset_read()

    # ------------------------------------------------------------------
    # read primitives
    # ------------------------------------------------------------------
    def read(self, num_bytes):
        """Read numBytes from the input buffer, fetching packets as needed."""
        if num_bytes < 0:
            raise ValueError("negative read size")
        ret = bytearray()
        clen = len(self.in_buffer)
        if clen > 0:
            take = min(clen, num_bytes)
            ret.extend(self.in_buffer[:take])
            del self.in_buffer[:take]
            num_bytes -= take
        while num_bytes > 0:
            if self.break_conn:
                self.break_conn = False
            pck = self.read_packet()
            if pck is None:  # data packet consumed into in_buffer
                clen = len(self.in_buffer)
                take = min(clen, num_bytes)
                ret.extend(self.in_buffer[:take])
                del self.in_buffer[:take]
                num_bytes -= take
                continue
            if is_marker_type(pck):
                self.process_marker()
                raise ErrConnReset()
            raise ValueError("receive abnormal packet type {} instead of data packet".format(
                pck.get_packet_type()))
        return bytes(ret)

    def process_marker(self):
        self.reset_write()
        marker = new_marker_packet(MARKER_TYPE_RESET, self.context)
        self.write_packet(marker)
        self.read_packet()
        return None

    def get_byte(self):
        rb = self.read(1)
        return rb[0]

    def get_int64(self, size, compress, big_endian):
        ret = 0
        neg_flag = False
        if compress:
            rb = self.read(1)[0]
            size = rb
            if size & 0x80:
                neg_flag = True
                size = size & 0x7F
            big_endian = True
        if size == 0:
            return 0
        if size > 8:
            raise ValueError("invalid size for GetInt64: {}".format(size))
        rb = self.read(size)
        if big_endian:
            ret = int.from_bytes(rb, "big", signed=False)
        else:
            ret = int.from_bytes(rb, "little", signed=False)
        if neg_flag:
            ret = ret * -1
        return ret

    def get_int(self, size, compress, big_endian):
        return self.get_int64(size, compress, big_endian)

    def get_clr(self):
        nb = self.get_byte()
        if nb == 0 or nb == 0xFF or nb == 0xFD:
            return None
        chunk_size = int(nb)
        chunks = bytearray()
        if chunk_size == 0xFE:
            while chunk_size > 0:
                if self.use_big_clr_chunks:
                    chunk_size = self.get_int(4, True, True)
                else:
                    chunk_size = self.get_byte()
                chunk = self.read(chunk_size)
                chunks.extend(chunk)
        else:
            chunk = self.read(chunk_size)
            chunks.extend(chunk)
        return bytes(chunks)

    def get_dlc(self):
        length = self.get_int(4, True, True)
        if length > 0:
            output = self.get_clr()
            if len(output) > length:
                output = output[:length]
            return output
        return None

    def get_bytes(self, length):
        return self.read(length)

    def get_key_val(self):
        key = self.get_dlc()
        val = self.get_dlc()
        num = self.get_int(4, True, True)
        return key, val, num

    def get_null_term_string(self, _max_size=None):
        data = bytearray()
        while True:
            b = self.get_byte()
            if b == 0:
                break
            data.append(b)
        return bytes(data).decode("utf-8", "replace")

    # ------------------------------------------------------------------
    # write primitives
    # ------------------------------------------------------------------
    def put_bytes(self, *data):
        for d in data:
            if isinstance(d, int):
                self.out_buffer.append(d)
            else:
                self.out_buffer.extend(d)

    def put_uint(self, number, size, big_endian, compress):
        num = int(number)
        if size == 1:
            self.out_buffer.append(num & 0xFF)
            return
        if compress:
            temp = num.to_bytes(8, "big")
            leading = len(temp) - len(temp.lstrip(b"\x00"))
            temp = temp[leading:]
            if size > len(temp):
                size = len(temp)
            if size == 0:
                self.out_buffer.append(0)
            else:
                self.out_buffer.append(size)
                self.out_buffer.extend(temp)
        else:
            if big_endian:
                self.out_buffer.extend(num.to_bytes(size, "big"))
            else:
                self.out_buffer.extend(num.to_bytes(size, "little"))

    def put_int(self, number, size, big_endian, compress):
        num = int(number)
        if compress:
            temp = (num & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "big")
            leading = len(temp) - len(temp.lstrip(b"\x00"))
            temp = temp[leading:]
            if size > len(temp):
                size = len(temp)
            if size == 0:
                self.out_buffer.append(0)
            else:
                self.out_buffer.append(size)
                self.out_buffer.extend(temp[:size])
        else:
            if size == 1:
                self.out_buffer.append(num & 0xFF)
            else:
                if big_endian:
                    self.out_buffer.extend((num & ((1 << (size * 8)) - 1)).to_bytes(size, "big"))
                else:
                    self.out_buffer.extend((num & ((1 << (size * 8)) - 1)).to_bytes(size, "little"))

    def put_clr(self, data):
        if data is None:
            data = b""
        data_len = len(data)
        if data_len > 0xFC:
            self.out_buffer.append(0xFE)
            start = 0
            while start < data_len:
                end = min(start + self.clr_chunk_size, data_len)
                temp = data[start:end]
                if self.use_big_clr_chunks:
                    self.put_int(len(temp), 4, True, True)
                else:
                    self.out_buffer.append(len(temp))
                self.out_buffer.extend(temp)
                start += self.clr_chunk_size
            self.out_buffer.append(0)
        elif data_len == 0:
            self.out_buffer.append(0)
        else:
            self.out_buffer.append(data_len)
            self.out_buffer.extend(data)

    def put_string(self, data):
        self.put_clr(data.encode("utf-8"))

    def put_key_val_string(self, key, val, num):
        self.put_key_val(key.encode("utf-8"), val.encode("utf-8"), num)

    def put_key_val(self, key, val, num):
        if not key:
            self.out_buffer.append(0)
        else:
            self.put_uint(len(key), 4, True, True)
            self.put_clr(key)
        if not val:
            self.out_buffer.append(0)
        else:
            self.put_uint(len(val), 4, True, True)
            self.put_clr(val)
        self.put_int(num, 4, True, True)

    # convenience
    def put_int_le(self, number, size):
        self.put_int(number, size, False, False)

    def put_int_be(self, number, size):
        self.put_int(number, size, True, False)

    def has_error(self):
        return self.summary is not None and (self.summary.ret_code != 0 and self.summary.ret_code != 1403)

    def get_error(self):
        err = OracleError()
        if self.has_error():
            err.err_code = self.summary.ret_code
            if self.summary.error_message:
                err.err_msg = self.summary.error_message.decode("utf-8", "replace")
            err.err_pos = self.summary.error_pos
        return err

    def raise_error(self):
        err = self.get_error()
        if err.err_code != 0:
            raise err


class _NilTracer:
    def print(self, *args, **kwargs):
        pass

    def printf(self, *args, **kwargs):
        pass

    def log_packet(self, *args, **kwargs):
        pass


def accept_packet_type():
    from .accept_packet import AcceptPacket
    return AcceptPacket


def redirect_type():
    from .refuse_packet import RedirectPacket
    return RedirectPacket


def refuse_type():
    from .refuse_packet import RefusePacket
    return RefusePacket


def is_marker_type(pck):
    return hasattr(pck, "marker_type")

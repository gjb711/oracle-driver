"""
TCPNego (O5LOGON step 1 / protocol negotiation) ported from
github.com/sijms/go-ora/v2 tcp_protocol_nego.go
"""


class TCPNego:
    def __init__(self):
        self.message_code = 0
        self.protocol_server_version = 0
        self.protocol_server_string = ""
        self.oracle_version = 0
        self.server_charset = 0
        self.server_flags = 0
        self.charset_elem = 0
        self.servern_charset = 0
        self.server_compile_time_caps = b""
        self.server_runtime_caps = b""


def new_tcp_nego(session):
    session.reset_buffer()
    session.put_bytes(1, 6, 0)
    session.put_bytes(b"OracleClientGo\x00")
    session.write()

    result = TCPNego()
    result.message_code = session.get_byte()
    if result.message_code != 1:
        raise IOError("message code error: received code {} and expected code is 1".format(result.message_code))
    result.protocol_server_version = session.get_byte()
    if result.protocol_server_version == 4:
        result.oracle_version = 7230
    elif result.protocol_server_version == 5:
        result.oracle_version = 8030
    elif result.protocol_server_version == 6:
        result.oracle_version = 8100
    else:
        raise IOError("unsupported server version")

    session.get_byte()
    result.protocol_server_string = session.get_null_term_string(50)

    result.server_charset = session.get_int(2, False, False)
    result.server_flags = session.get_byte()
    result.charset_elem = session.get_int(2, False, False)
    if result.charset_elem > 0:
        session.get_bytes(result.charset_elem * 5)

    len1 = session.get_int(2, False, True)
    num_array = session.get_bytes(len1)
    num3 = 6 + num_array[5] + num_array[6]
    result.servern_charset = int.from_bytes(num_array[(num3 + 3):(num3 + 5)], "big")

    len2 = session.get_byte()
    result.server_compile_time_caps = session.get_bytes(len2)
    len3 = session.get_byte()
    result.server_runtime_caps = session.get_bytes(len3)

    if len(result.server_compile_time_caps) > 15 and result.server_compile_time_caps[15] & 1:
        session.has_eos_capability = True
    if len(result.server_compile_time_caps) > 16 and result.server_compile_time_caps[16] & 1:
        session.has_fsap_capability = True
    if not result.server_compile_time_caps or len(result.server_compile_time_caps) < 8:
        raise IOError("server compile time caps length less than 8")
    if len(result.server_compile_time_caps) > 37 and result.server_compile_time_caps[37] & 32:
        session.use_big_clr_chunks = True
        session.clr_chunk_size = 0x7FFF
    return result

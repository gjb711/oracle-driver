"""
DBVersion ported from github.com/sijms/go-ora/v2 db_version.go
"""


class DBVersion:
    def __init__(self):
        self.info = ""
        self.text = ""
        self.number = 0
        self.major_version = 0
        self.minor_version = 0
        self.patchset_version = 0

    def __str__(self):
        return self.text


def get_db_version(session):
    session.reset_buffer()
    session.put_bytes(3, 0x3B, 0, 1)
    session.put_uint(0x100, 2, True, True)
    session.put_bytes(1, 1)
    if session.ttc_version >= 11:
        session.put_uint(1, 4, True, True)
    session.write()
    msg = session.get_byte()
    if msg != 8:
        raise IOError("message code error: received code {} and expected code is 8".format(msg))
    length = session.get_int(2, True, True)
    info = session.get_string(length)
    number = session.get_int(4, True, True)

    version = ((number >> 24 & 0xFF) * 1000 + (number >> 20 & 0xF) * 100
               + (number >> 12 & 0xF) * 10 + (number >> 8 & 0xF))
    text = "{}.{}.{}.{}.{}".format(number >> 24 & 0xFF, number >> 20 & 0xF,
                                   number >> 12 & 0xF, number >> 8 & 0xF, number & 0xFF)
    ret = DBVersion()
    ret.info = info
    ret.text = text
    ret.number = version
    ret.major_version = number >> 24 & 0xFF
    ret.minor_version = number >> 20 & 0xF
    ret.patchset_version = number >> 8 & 0xF
    return ret

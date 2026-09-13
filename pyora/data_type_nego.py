"""
DataTypeNego (O5LOGON step 2 / DTY negotiation) ported from
github.com/sijms/go-ora/v2 data_type_nego.go
"""

import time
import datetime
from zoneinfo import ZoneInfo

BUFFER_GROW = 2369
TNS_TYPE_REP_NATIVE = 0
TNS_TYPE_REP_UNIVERSAL = 1
TNS_TYPE_REP_ORACLE = 10

TNS_DATA_TYPE_VBI = 15
TNS_DATA_TYPE_CURSOR = 102
TNS_DATA_TYPE_RDD = 104
TNS_DATA_TYPE_CLOB = 112
TNS_DATA_TYPE_BLOB = 113
TNS_DATA_TYPE_BFILE = 114
TNS_DATA_TYPE_CFILE = 115
TNS_DATA_TYPE_RSET = 116
TNS_DATA_TYPE_DCLOB = 195
TNS_DATA_TYPE_DBLOB = 196
TNS_DATA_TYPE_DBFILE = 197
TNS_DATA_TYPE_UROWID = 208
TNS_DATA_TYPE_EXT_NAMED = 108
TNS_DATA_TYPE_INT_NAMED = 109
TNS_DATA_TYPE_EXT_REF = 110
TNS_DATA_TYPE_INT_REF = 111

# OracleType values -- must match go-ora's TNSType enum (v2/parameter.go),
# NOT the OCI native dty codes.  These are the logical type ids emitted in
# the DTY type table.
NCHAR = 1
NUMBER = 2
LONG = 8
DATE = 12
RAW = 23
LongRaw = 24
ROWID = 11
BInteger = 3
FLOAT = 4
NullStr = 5
VarNum = 6
PDN = 7
VARCHAR = 9
JSON = 119
VECTOR = 127


class DataTypeNego:
    def __init__(self, message_code=2, server=None):
        self.message_code = message_code
        self.server = server
        self.type_and_rep = [0] * BUFFER_GROW
        self.runtime_type_and_rep = []
        self.data_type_rep_for_1100 = 0
        self.data_type_rep_for_1200 = 0
        self.compile_time_caps = bytearray([
            6, 1, 0, 0, 106, 1, 1, 11,
            1, 1, 1, 1, 1, 1, 0, 41,
            144, 3, 7, 3, 0, 1, 0, 235,
            1, 0, 5, 1, 0, 0, 0, 24,
            0, 0, 7, 32, 2, 58, 0, 0,
            5, 0, 0, 0, 8,
        ])
        self.runtime_cap = bytearray([2, 1, 0, 0, 0, 0, 0])
        self.b32k_type_supported = False
        self.support_session_state_ops = False
        self.server_tz_version = 0
        self.client_tz_version = 0x20

    def add_type_rep(self, dty, ndty, rep):
        idx = self.type_and_rep[0]
        if idx + 4 > len(self.type_and_rep):
            self.type_and_rep.extend([0] * BUFFER_GROW)
        self.type_and_rep[idx] = dty
        self.type_and_rep[idx + 1] = ndty
        if ndty == 0:
            self.type_and_rep[0] = idx + 2
        else:
            self.type_and_rep[idx + 2] = rep
            self.type_and_rep[idx + 3] = 0
            self.type_and_rep[0] = idx + 4

    def read(self, session):
        msg = session.get_byte()
        if msg != 2:
            raise IOError("message code error: received code {} and expected code is 2".format(msg))
        zone = None
        if self.runtime_cap[1] == 1:
            tz_bytes = session.get_bytes(11)
            if len(tz_bytes) < 11:
                raise IOError("incorrect format for DBTimeZone")
            tz_hours = tz_bytes[4] - 60
            tz_min = tz_bytes[5] - 60
            tz_sec = tz_bytes[6] - 60
            zone = datetime.timezone(datetime.timedelta(
                hours=tz_hours, minutes=tz_min, seconds=tz_sec))
            if self.compile_time_caps[37] & 2 == 2:
                self.server_tz_version = session.get_int(4, False, True)
        level = 0
        while True:
            if self.compile_time_caps[27] == 0:
                num = session.get_int(1, False, False)
            else:
                num = session.get_int(2, False, True)
            if num == 0 and level == 0:
                break
            if num == 0 and level == 1:
                level = 0
                continue
            if level == 3:
                level = 0
                continue
            level += 1
        return zone

    def write(self, session):
        session.reset_buffer()
        if self.server.server_compile_time_caps is None or len(self.server.server_compile_time_caps) <= 27 \
                or self.server.server_compile_time_caps[27] == 0:
            self.compile_time_caps[27] = 0
        session.put_bytes(self.message_code)
        session.put_int(self.server.server_charset, 2, False, False)  # client remote in
        session.put_int(self.server.server_charset, 2, False, False)  # client remote out
        session.put_bytes(self.server.server_flags, len(self.compile_time_caps))
        session.put_bytes(bytes(self.compile_time_caps))
        session.put_bytes(len(self.runtime_cap))
        session.put_bytes(bytes(self.runtime_cap))
        if self.runtime_cap[1] & 1 == 1:
            session.put_bytes(tz_bytes())
            if self.compile_time_caps[37] & 2 == 2:
                session.put_int(self.client_tz_version, 4, True, False)
        session.put_int(self.server.servern_charset, 2, False, False)
        size = self.runtime_type_and_rep[0]
        if self.compile_time_caps[27] == 0:
            for x in self.runtime_type_and_rep[1:size]:
                session.put_bytes(x)
            session.put_bytes(0)
        else:
            for x in self.runtime_type_and_rep[1:size]:
                session.put_int(x, 2, True, False)
            session.put_bytes(0, 0)
        session.write()


def tz_bytes():
    now = datetime.datetime.now().astimezone()
    offset = now.utcoffset()
    total = int(offset.total_seconds()) if offset else 0
    hours = int(total // 3600)
    minutes = int((total // 60) % 60)
    seconds = int(total % 60)
    return bytes([128, 0, 0, 0,
                  (hours + 60) & 0xFF,
                  (minutes + 60) & 0xFF,
                  (seconds + 60) & 0xFF,
                  128, 0, 0, 0])


def build_type_nego(nego, session):
    result = DataTypeNego(message_code=2, server=nego)
    if len(nego.server_compile_time_caps) <= 27 or nego.server_compile_time_caps[27] == 0:
        result.compile_time_caps[27] = 0
    xml_type_client_side_decoding = False
    if len(nego.server_compile_time_caps) > 7:
        if nego.server_compile_time_caps[7] >= 8 and xml_type_client_side_decoding:
            result.compile_time_caps[36] = 4
        elif nego.server_compile_time_caps[7] < 7:
            result.compile_time_caps[36] = 0
    if len(nego.server_runtime_caps) < 1 or nego.server_runtime_caps[1] & 1 != 1:
        result.runtime_cap[1] = 0
    if len(nego.server_runtime_caps) > 6:
        if nego.server_runtime_caps[6] & 4 == 4:
            result.runtime_cap[6] |= 4
            result.b32k_type_supported = True
        if nego.server_runtime_caps[6] & 16 == 16:
            result.support_session_state_ops = True
        if nego.server_runtime_caps[6] & 2 == 2:
            result.runtime_cap[6] |= 2
    if len(nego.server_compile_time_caps) <= 37 or nego.server_compile_time_caps[37] & 2 != 2:
        result.compile_time_caps[37] = 0
        result.compile_time_caps[1] = 0

    result.type_and_rep[0] = 1
    entries = [
        (NCHAR, NCHAR, TNS_TYPE_REP_UNIVERSAL),
        (NUMBER, NUMBER, TNS_TYPE_REP_ORACLE),
        (LONG, LONG, TNS_TYPE_REP_UNIVERSAL),
        (DATE, DATE, TNS_TYPE_REP_ORACLE),
        (RAW, RAW, TNS_TYPE_REP_UNIVERSAL),
        (LongRaw, LongRaw, TNS_TYPE_REP_UNIVERSAL),
        (25, 25, TNS_TYPE_REP_UNIVERSAL), (26, 26, TNS_TYPE_REP_UNIVERSAL),
        (27, 27, TNS_TYPE_REP_UNIVERSAL), (28, 28, TNS_TYPE_REP_UNIVERSAL),
        (29, 29, TNS_TYPE_REP_UNIVERSAL), (30, 30, TNS_TYPE_REP_UNIVERSAL),
        (31, 31, TNS_TYPE_REP_UNIVERSAL), (32, 32, TNS_TYPE_REP_UNIVERSAL),
        (33, 33, TNS_TYPE_REP_UNIVERSAL), (10, 10, TNS_TYPE_REP_UNIVERSAL),
        (ROWID, ROWID, TNS_TYPE_REP_UNIVERSAL),
        (40, 40, TNS_TYPE_REP_UNIVERSAL), (41, 41, TNS_TYPE_REP_UNIVERSAL),
        (117, 117, TNS_TYPE_REP_UNIVERSAL), (120, 120, TNS_TYPE_REP_UNIVERSAL),
    ]
    for dty, ndty, rep in entries:
        result.add_type_rep(dty, ndty, rep)
    # large run of 1:1 types
    for v in [290, 291, 292, 293, 294, 298, 299, 300, 301, 302, 303, 304, 305,
              306, 307, 308, 309, 310, 311, 312, 313, 315, 316, 317, 318, 319,
              320, 321, 322, 323, 327, 328, 329, 331, 333, 334, 335, 336, 337,
              338, 339, 340, 341, 342, 343, 344, 345, 346, 348, 349, 354, 355,
              359, 363, 380, 381, 382, 383, 384, 385, 386, 387, 388, 389, 390,
              391, 393, 394, 395, 396, 397, 398, 399, 400, 401, 404, 405, 406,
              407, 413, 414, 415, 416, 417, 418, 419, 420, 421, 422, 423, 424,
              425, 426, 427, 429, 430, 431, 432, 433, 449, 450, 454, 455, 456,
              457, 458, 459, 460, 461, 462, 463, 466, 467, 468, 469, 470, 471,
              472, 473, 474, 475, 476, 477, 478, 479, 480, 481, 482, 483, 484,
              485, 486, 490, 491, 492, 493, 494, 495, 496, 498, 499, 500, 501,
              502, 509, 510, 513, 514, 516, 517, 518, 519, 520, 521, 522, 523,
              524, 525, 526, 527, 528, 529, 530, 531, 532, 533, 534, 535, 536,
              537, 538, 539, 540, 541, 542, 543]:
        result.add_type_rep(v, v, TNS_TYPE_REP_UNIVERSAL)
    for v in [560, 565, 572, 573, 574, 575, 576, 578, 563, 564, 579, 580, 581,
              582, 583, 584, 585]:
        result.add_type_rep(v, v, TNS_TYPE_REP_UNIVERSAL)
    result.add_type_rep(BInteger, NUMBER, TNS_TYPE_REP_ORACLE)
    result.add_type_rep(FLOAT, NUMBER, TNS_TYPE_REP_ORACLE)
    result.add_type_rep(NullStr, NCHAR, TNS_TYPE_REP_UNIVERSAL)
    result.add_type_rep(VarNum, NUMBER, TNS_TYPE_REP_ORACLE)
    result.add_type_rep(PDN, NUMBER, TNS_TYPE_REP_ORACLE)
    result.add_type_rep(VARCHAR, NCHAR, TNS_TYPE_REP_UNIVERSAL)
    result.add_type_rep(TNS_DATA_TYPE_VBI, NCHAR, TNS_TYPE_REP_UNIVERSAL)
    result.add_type_rep(39, 120, TNS_TYPE_REP_UNIVERSAL)
    result.add_type_rep(58, 0, TNS_TYPE_REP_NATIVE)
    result.add_type_rep(68, 2, TNS_TYPE_REP_ORACLE)
    result.add_type_rep(69, 0, TNS_TYPE_REP_NATIVE)
    result.add_type_rep(70, 0, TNS_TYPE_REP_NATIVE)
    result.add_type_rep(74, 0, TNS_TYPE_REP_NATIVE)
    result.add_type_rep(76, 0, TNS_TYPE_REP_NATIVE)
    result.add_type_rep(91, 2, TNS_TYPE_REP_ORACLE)
    result.add_type_rep(94, 1, TNS_TYPE_REP_UNIVERSAL)
    result.add_type_rep(95, 23, TNS_TYPE_REP_UNIVERSAL)
    result.add_type_rep(96, 96, TNS_TYPE_REP_UNIVERSAL)
    result.add_type_rep(97, 96, TNS_TYPE_REP_UNIVERSAL)
    result.add_type_rep(100, 100, TNS_TYPE_REP_UNIVERSAL)
    result.add_type_rep(101, 101, TNS_TYPE_REP_UNIVERSAL)
    result.add_type_rep(TNS_DATA_TYPE_CURSOR, TNS_DATA_TYPE_CURSOR, TNS_TYPE_REP_UNIVERSAL)
    result.add_type_rep(TNS_DATA_TYPE_RDD, ROWID, TNS_TYPE_REP_UNIVERSAL)
    result.add_type_rep(105, 0, TNS_TYPE_REP_NATIVE)
    result.add_type_rep(106, 106, TNS_TYPE_REP_UNIVERSAL)
    result.add_type_rep(TNS_DATA_TYPE_EXT_NAMED, TNS_DATA_TYPE_INT_NAMED, TNS_TYPE_REP_UNIVERSAL)
    result.add_type_rep(TNS_DATA_TYPE_INT_NAMED, TNS_DATA_TYPE_INT_NAMED, TNS_TYPE_REP_UNIVERSAL)
    result.add_type_rep(TNS_DATA_TYPE_EXT_REF, TNS_DATA_TYPE_INT_REF, TNS_TYPE_REP_UNIVERSAL)
    result.add_type_rep(TNS_DATA_TYPE_INT_REF, TNS_DATA_TYPE_INT_REF, TNS_TYPE_REP_UNIVERSAL)
    result.add_type_rep(TNS_DATA_TYPE_CLOB, TNS_DATA_TYPE_CLOB, TNS_TYPE_REP_UNIVERSAL)
    result.add_type_rep(TNS_DATA_TYPE_BLOB, TNS_DATA_TYPE_BLOB, TNS_TYPE_REP_UNIVERSAL)
    result.add_type_rep(TNS_DATA_TYPE_BFILE, TNS_DATA_TYPE_BFILE, TNS_TYPE_REP_UNIVERSAL)
    result.add_type_rep(TNS_DATA_TYPE_CFILE, TNS_DATA_TYPE_CFILE, TNS_TYPE_REP_UNIVERSAL)
    result.add_type_rep(TNS_DATA_TYPE_RSET, TNS_DATA_TYPE_CURSOR, TNS_TYPE_REP_UNIVERSAL)
    result.add_type_rep(118, 0, TNS_TYPE_REP_NATIVE)
    result.add_type_rep(JSON, JSON, TNS_TYPE_REP_NATIVE)
    result.add_type_rep(121, 0, TNS_TYPE_REP_NATIVE)
    result.add_type_rep(122, 0, TNS_TYPE_REP_NATIVE)
    result.add_type_rep(123, 0, TNS_TYPE_REP_NATIVE)
    result.add_type_rep(VECTOR, VECTOR, TNS_TYPE_REP_UNIVERSAL)
    result.add_type_rep(136, 0, TNS_TYPE_REP_NATIVE)
    result.add_type_rep(146, 146, TNS_TYPE_REP_UNIVERSAL)
    result.add_type_rep(147, 0, TNS_TYPE_REP_NATIVE)
    result.add_type_rep(152, 2, TNS_TYPE_REP_ORACLE)
    result.add_type_rep(153, 2, TNS_TYPE_REP_ORACLE)
    result.add_type_rep(154, 2, TNS_TYPE_REP_ORACLE)
    result.add_type_rep(155, 1, TNS_TYPE_REP_UNIVERSAL)
    result.add_type_rep(156, 12, TNS_TYPE_REP_ORACLE)
    result.add_type_rep(172, 2, TNS_TYPE_REP_ORACLE)
    for v in [178, 179, 180, 181, 182, 183]:
        result.add_type_rep(v, v, TNS_TYPE_REP_UNIVERSAL)
    result.add_type_rep(184, 12, TNS_TYPE_REP_ORACLE)
    result.add_type_rep(185, 185, TNS_TYPE_REP_UNIVERSAL)
    result.add_type_rep(186, 186, TNS_TYPE_REP_UNIVERSAL)
    result.add_type_rep(187, 187, TNS_TYPE_REP_UNIVERSAL)
    result.add_type_rep(188, 188, TNS_TYPE_REP_UNIVERSAL)
    result.add_type_rep(189, 189, TNS_TYPE_REP_UNIVERSAL)
    result.add_type_rep(190, 190, TNS_TYPE_REP_UNIVERSAL)
    result.add_type_rep(191, 0, TNS_TYPE_REP_NATIVE)
    result.add_type_rep(192, 0, TNS_TYPE_REP_NATIVE)
    result.add_type_rep(TNS_DATA_TYPE_DCLOB, TNS_DATA_TYPE_CLOB, TNS_TYPE_REP_UNIVERSAL)
    result.add_type_rep(TNS_DATA_TYPE_DBLOB, TNS_DATA_TYPE_BLOB, TNS_TYPE_REP_UNIVERSAL)
    result.add_type_rep(TNS_DATA_TYPE_DBFILE, TNS_DATA_TYPE_BFILE, TNS_TYPE_REP_UNIVERSAL)
    result.add_type_rep(TNS_DATA_TYPE_UROWID, TNS_DATA_TYPE_UROWID, TNS_TYPE_REP_UNIVERSAL)
    result.add_type_rep(209, 0, TNS_TYPE_REP_NATIVE)
    result.add_type_rep(231, 231, TNS_TYPE_REP_UNIVERSAL)
    result.add_type_rep(232, 231, TNS_TYPE_REP_UNIVERSAL)
    result.add_type_rep(233, 233, TNS_TYPE_REP_UNIVERSAL)
    result.add_type_rep(252, 252, TNS_TYPE_REP_UNIVERSAL)
    result.add_type_rep(241, TNS_DATA_TYPE_INT_NAMED, TNS_TYPE_REP_UNIVERSAL)
    result.add_type_rep(515, 0, TNS_TYPE_REP_NATIVE)

    result.data_type_rep_for_1100 = result.type_and_rep[0]
    for v in [590, 591, 592, 613, 614, 615, 616, 611, 612, 593, 594, 595, 596,
              597, 598, 599, 600, 601, 602, 603, 604, 605]:
        result.add_type_rep(v, v, TNS_TYPE_REP_UNIVERSAL)
    for v in [622, 623, 624, 625, 626, 627, 628, 629, 630, 631, 632, 637, 638, 636]:
        result.add_type_rep(v, v, TNS_TYPE_REP_UNIVERSAL)
    result.data_type_rep_for_1200 = result.type_and_rep[0]
    result.add_type_rep(639, 639, TNS_TYPE_REP_UNIVERSAL)
    result.add_type_rep(640, 640, TNS_TYPE_REP_UNIVERSAL)

    # go-ora's buildDataTypeNegotiation slices RuntimeTypeAndRep to
    # [:DataTypeRepFor1100] / [:DataTypeRepFor1200] when the server's TTC
    # version (cap[7]) is < 7 / < 8.  However the write loop iterates
    # RuntimeTypeAndRep[1:size] where size == TypeAndRep[0] (the *full* final
    # index), so sending the truncated slice would either panic or drop the
    # trailing 590..640 rows.  The Oracle 11g server rejects the truncated
    # table (pyora saw a connection reset / marker), and go-ora's verified
    # working trace sends the FULL table (2631-byte DTY).  Match go-ora: send
    # the complete type table regardless of cap[7].
    result.runtime_type_and_rep = result.type_and_rep
    import os as _os
    if _os.environ.get("PYORA_DEBUG"):
        _rt = result.runtime_type_and_rep
        print("DBG runtime_type_and_rep len={} idx0={} first30={}".format(
            len(_rt), _rt[0] if len(_rt) > 0 else None, _rt[1:31]),
            file=__import__("sys").stderr)
        print("DBG full type_and_rep len={} idx0={} datatype1100={} datatype1200={}".format(
            len(result.type_and_rep), result.type_and_rep[0],
            result.data_type_rep_for_1100, result.data_type_rep_for_1200),
            file=__import__("sys").stderr)
    return result

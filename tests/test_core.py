"""
Consolidated verification suite for the pyora driver (go-ora v2 port).

Runs byte-level checks across every layer of the port. No live Oracle is
required: the wire-format writers are verified against go-ora's known output
vectors and via encode/decode round-trips. Run with:

    python -m tests.test_core        (from G:\\ai\\oracledb)
"""

import datetime

from pyora import __version__
from pyora.configurations import parse_config
from pyora.network.session import Session
from pyora.network.connect_packet import new_connect_packet
from pyora.network.data_packet import new_data_packet, new_data_packet_from_data
from pyora.converters.number import decode_number, encode_number
from pyora.converters.strings import new_string_converter
from pyora.parameter_encode import encode_parameter_value, encode_value_binary

PASS = 0
FAIL = 0


def check(label, ok, extra=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print("  OK  {}".format(label) + (("  -- " + str(extra)) if extra else ""))
    else:
        FAIL += 1
        print("  FAIL {}".format(label) + (("  -- " + str(extra)) if extra else ""))


def test_number():
    print("[number] Oracle NUMBER binary encode/decode")
    cases = [0, 1, -1, 255, 123.456, 100000, -0.0001, 42, 1e10]
    vectors = {
        0: "80", 1: "c102", -1: "3e6466", 255: "c20338", 42: "c12b",
    }
    all_ok = True
    for v in cases:
        enc = encode_number(v)
        dec = decode_number(enc)
        ok = (dec == v) or (isinstance(dec, float) and isinstance(v, float)
                            and abs(dec - v) < 1e-9 * abs(v))
        if not ok:
            all_ok = False
        check("round-trip {!r}".format(v), ok, dec)
    for v, expected in vectors.items():
        check("byte vector {!r} == 0x{}".format(v, expected),
              encode_number(v).hex() == expected,
              encode_number(v).hex())


def test_config_connect():
    print("[config] connection-string parsing + connect descriptor")
    cfg = parse_config("oracle://scott:tiger@localhost:1521/XEPDB1?CHARSET=AL32UTF8")
    check("user_id", cfg.user_id == "scott", cfg.user_id)
    check("service_name", cfg.service_name == "XEPDB1", cfg.service_name)
    check("charset_id AL32UTF8", cfg.charset_id == 0x369, hex(cfg.charset_id))
    cd = cfg.connection_data()
    check("descriptor has HOST", "HOST=localhost" in cd, cd)
    check("descriptor has SERVICE_NAME", "SERVICE_NAME=XEPDB1" in cd)


def test_session_serialization():
    print("[session] TTC serialization round-trips (CLR / KeyVal / uint)")
    s = Session()
    data = b"oracle wire data " * 30
    s.out_buffer = bytearray()
    s.put_clr(data)
    s.in_buffer = bytearray(bytes(s.out_buffer))
    check("CLR round-trip", s.get_clr() == data)

    s2 = Session()
    s2.out_buffer = bytearray()
    s2.put_key_val_string("AUTH_TERMINAL", "host1", 0)
    s2.in_buffer = bytearray(bytes(s2.out_buffer))
    k, v, n = s2.get_key_val()
    check("KeyVal round-trip", k == b"AUTH_TERMINAL" and v == b"host1" and n == 0)

    s3 = Session()
    s3.out_buffer = bytearray()
    for val in [0, 1, 128, 65535, 1000000]:
        s3.put_uint(val, 4, True, True)
    s3.in_buffer = bytearray(bytes(s3.out_buffer))
    ok = all(s3.get_int(4, True, True) == val for val in [0, 1, 128, 65535, 1000000])
    check("compressed uint round-trips", ok)


def test_packets():
    print("[packets] connect / data packet framing")
    cfg = parse_config("oracle://scott:tiger@localhost:1521/XEPDB1")
    s = Session(cfg)
    cp = new_connect_packet(s.context)
    b = cp.bytes()
    check("connect packet type=1", b[4] == 1)
    check("connect packet length", int.from_bytes(b[0:2], "big") == cp.length,
          cp.length)

    dp = new_data_packet(b"hello", s.context)
    dp2 = new_data_packet_from_data(dp.bytes(), s.context)
    check("data packet round-trip", dp2.buffer == b"hello")


def test_string_converter():
    print("[strings] charset conversion")
    sc = new_string_converter(0x369)  # AL32UTF8
    check("AL32UTF8 round-trip", sc.decode(sc.encode("h\u00e9llo")) == "h\u00e9llo")
    sc2 = new_string_converter(0xb2)  # WE8MSWIN1252
    check("WE8MSWIN1252 round-trip", sc2.decode(sc2.encode("caf\u00e9")) == "caf\u00e9")


def test_parameter_encode():
    print("[parameter] bind value encoding")
    cfg = parse_config("oracle://scott:tiger@localhost:1521/XEPDB1")
    s = Session(cfg)
    from pyora.connection import Connection
    cn = Connection(config=cfg)

    class FakeSession(Session):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            self.capture = bytearray()

        def put_clr(self, data):
            if data is None:
                self.capture.append(0)
            else:
                self.capture.append(len(data))
                self.capture.extend(data)

    fs = FakeSession()
    # int -> NUMBER
    encode_parameter_value(5, 2, cn, fs)
    # Oracle NUMBER for 5 is c1 06; put_clr prefixes a length byte 0x02
    check("int bind == 02c106", bytes(fs.capture).hex() == "02c106",
          bytes(fs.capture).hex())
    # None -> null indicator 0x00
    fs2 = FakeSession()
    encode_parameter_value(None, 2, cn, fs2)
    check("null bind == 00", bytes(fs2.capture).hex() == "00")


def main():
    print("pyora {} consolidated self-test".format(__version__))
    for t in (test_number, test_config_connect, test_session_serialization,
              test_packets, test_string_converter, test_parameter_encode):
        t()
    print("=" * 70)
    print("PASS={} FAIL={} TOTAL={}".format(PASS, FAIL, PASS + FAIL))
    print("=" * 70)
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    import sys
    sys.exit(main())

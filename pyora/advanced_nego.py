"""
Advanced negotiation (O5/network services) ported from
github.com/sijms/go-ora/v2 advanced_nego/*.

Runs between the connect/accept handshake and the TCP/data-type negotiation.
For a plain, no-encryption, no-integrity connection the negotiation simply
exchanges the DEADBEEF request/response and selects no algorithm, so no
encryption or checksum layers are installed.
"""

from .network.session import Session


DEADBEEF = 0xDEADBEEF
NEGO_VERSION = 0x0B200200


class AdvancedNegoComm:
    def __init__(self, session):
        self.session = session

    def write_packet_header(self, length, _type):
        self.session.put_int(length, 2, True, False)
        self.session.put_int(_type, 2, True, False)

    def read_packet_header(self, _type):
        length = self.session.get_int(2, False, True)
        received_type = self.session.get_int(2, False, True)
        if received_type != _type:
            raise ValueError("advanced negotiation error: received type is not as stored type")
        self.validate_packet_header(length, received_type)
        return length

    def validate_packet_header(self, length, _type):
        if _type < 0 or _type > 7:
            raise ValueError("advanced negotiation error: cannot validate packet header")
        if _type in (0, 1):
            return
        if _type == 2:
            if length > 1:
                raise ValueError("advanced negotiation error: cannot validate packet header")
        elif _type in (3, 6):
            if length > 2:
                raise ValueError("advanced negotiation error: cannot validate packet header")
        elif _type in (4, 5):
            if length > 4:
                raise ValueError("advanced negotiation error: cannot validate packet header")
        elif _type == 7:
            if length < 10:
                raise ValueError("advanced negotiation error: cannot validate packet header")

    def read_ub1(self):
        self.read_packet_header(2)
        return self.session.get_byte()

    def write_ub1(self, number):
        self.write_packet_header(1, 2)
        self.session.put_bytes(number)

    def read_ub2(self):
        self.read_packet_header(3)
        return self.session.get_int(2, False, True)

    def write_ub2(self, number):
        self.write_packet_header(2, 3)
        self.session.put_int(number, 2, True, False)

    def read_ub4(self):
        self.read_packet_header(4)
        return self.session.get_int(4, False, True)

    def write_ub4(self, number):
        self.write_packet_header(4, 4)
        self.session.put_int(number, 4, True, False)

    def read_string(self):
        string_len = self.read_packet_header(0)
        return self.session.get_bytes(string_len)

    def write_string(self, input_bytes):
        self.write_packet_header(len(input_bytes), 0)
        self.session.put_bytes(input_bytes)

    def write_status(self, status):
        self.write_packet_header(2, 6)
        self.session.put_int(status, 2, True, False)

    def read_status(self):
        self.read_packet_header(6)
        return self.session.get_int(2, False, True)

    def read_version(self):
        self.read_packet_header(5)
        return self.session.get_int(4, False, True)

    def write_version(self, version):
        self.write_packet_header(4, 5)
        self.session.put_int(version, 4, True, False)

    def read_bytes(self):
        length = self.read_packet_header(1)
        return self.session.get_bytes(length)

    def write_bytes(self, input_bytes):
        self.write_packet_header(len(input_bytes), 1)
        self.session.put_bytes(input_bytes)

    def read_ub2_array(self):
        self.read_packet_header(1)
        num1 = self.session.get_int64(4, False, True)
        num2 = self.session.get_int(2, False, True)
        size = self.session.get_int(4, False, True)
        if num1 != DEADBEEF or num2 != 3:
            raise ValueError("advanced negotiation error: reading supervisor service")
        return [self.session.get_int(2, False, True) for _ in range(size)]

    def write_ub2_array(self, array):
        self.write_packet_header(10 + len(array) * 2, 1)
        self.session.put_int(DEADBEEF, 4, True, False)
        self.session.put_int(3, 2, True, False)
        self.session.put_int(len(array), 4, True, False)
        for item in array:
            self.session.put_int(item, 2, True, False)


class DefaultService:
    def __init__(self, comm, service_type, version, level=-1):
        self.comm = comm
        self.service_type = service_type
        self.level = level
        self.version = version
        self.available_service_names = []
        self.available_service_ids = []
        self.selected_indices = []

    def get_version(self):
        return self.version

    def activate_algorithm(self):
        return None

    def write_header(self, service_sub_packets):
        self.comm.session.put_int(self.service_type, 2, True, False)
        self.comm.session.put_int(service_sub_packets, 2, True, False)
        self.comm.session.put_int(0, 4, True, False)

    def build_service_list(self, user_list, use_level, use_default):
        self.selected_indices = []
        if use_level:
            if self.level == 1:
                self.selected_indices.append(0)
                return
            if self.level != 0 and self.level != 2 and self.level != 3:
                raise ValueError("unsupported service level value: {}".format(self.level))
        user_list = [u.strip() for u in user_list]
        if user_list and user_list[-1] == "":
            user_list = user_list[:-1]
        if not user_list:
            if use_default:
                for i in range(len(self.available_service_names)):
                    if self.available_service_names[i] == "" and not (use_level and self.level == 0):
                        continue
                    self.selected_indices.append(i)
                if use_level and self.level == 2:
                    self.selected_indices.append(0)
            return
        if len(user_list) == 1:
            upper = user_list[0].upper()
            if upper == "ALL":
                for i in range(len(self.available_service_names)):
                    if self.available_service_names[i] == "" and not (use_level and self.level == 0):
                        continue
                    self.selected_indices.append(i)
                if use_level and self.level == 2:
                    self.selected_indices.append(0)
                return
            if upper == "NONE":
                return
        if use_level and self.level == 0:
            self.selected_indices.append(0)
        names_upper = [n.upper() for n in self.available_service_names]
        for user_item in user_list:
            if user_item == "":
                raise ValueError("empty authentication service")
            found = False
            for i in range(len(names_upper)):
                if user_item.upper() == names_upper[i]:
                    self.selected_indices.append(i)
                    found = True
                    break
            if not found:
                raise ValueError("unsupported authentication service")
        if use_level and self.level == 2:
            self.selected_indices.append(0)


class SupervisorService(DefaultService):
    def __init__(self, comm):
        super().__init__(comm, 4, NEGO_VERSION)
        self.cid = bytes([0, 0, 16, 28, 102, 236, 40, 234])
        self.serv_array = [4, 1, 2, 3]

    def read_service_data(self, sub_packet_num):
        self.read_version_comm()
        status = self.comm.read_status()
        if status != 31:
            raise ValueError("advanced negotiation error: reading supervisor service")
        self.serv_array = self.comm.read_ub2_array()
        return None

    def read_version_comm(self):
        self.version = self.comm.read_version()

    def write_service_data(self):
        self.write_header(3)
        self.comm.write_version(self.get_version())
        self.comm.write_bytes(self.cid)
        self.comm.write_ub2_array(self.serv_array)

    def get_service_data_length(self):
        return 12 + len(self.cid) + 4 + 10 + (len(self.serv_array) * 2)


class AuthService(DefaultService):
    def __init__(self, comm):
        super().__init__(comm, 1, NEGO_VERSION, level=-1)
        self.status = 0xFCFF
        self.service_name = None
        self.active = False
        self.available_service_names = ["", "NTS", "KERBEROS5", "TCPS"]
        self.available_service_ids = [0, 1, 1, 2]
        self.build_service_list([], False, False)

    def write_service_data(self):
        self.write_header(3 + (len(self.selected_indices) * 2))
        self.comm.write_version(self.get_version())
        self.comm.write_ub2(0xE0E1)
        self.comm.write_status(self.status)
        for index in self.selected_indices:
            self.comm.write_ub1(self.available_service_ids[index])
            self.comm.write_string(self.available_service_names[index].encode("utf-8"))

    def read_service_data(self, sub_packet_num):
        self.version = self.comm.read_version()
        status = self.comm.read_status()
        if status == 0xFAFF and sub_packet_num > 2:
            self.comm.read_ub1()
            self.service_name = self.comm.read_string()
            if sub_packet_num > 4:
                self.comm.read_version()
                self.comm.read_ub4()
                self.comm.read_ub4()
            self.active = True
        else:
            if status != 0xFBFF:
                raise ValueError("advanced negotiation error: reading authentication service")
            self.active = False
        return None

    def get_service_data_length(self):
        size = 20
        for index in self.selected_indices:
            size = size + 5 + (4 + len(self.available_service_names[index]))
        return size


class EncryptService(DefaultService):
    def __init__(self, comm):
        super().__init__(comm, 2, NEGO_VERSION, level=0)
        self.algo_id = 0
        self.available_service_names = [
            "", "RC4_40", "RC4_56", "RC4_128", "RC4_256", "DES40C", "DES56C",
            "3DES112", "3DES168", "AES128", "AES192", "AES256",
        ]
        self.available_service_ids = [0, 1, 8, 10, 6, 3, 2, 11, 12, 15, 16, 17]
        self.build_service_list(
            ["RC4_40", "RC4_56", "RC4_128", "RC4_256", "DES56C", "AES128", "AES192", "AES256"],
            True, True)

    def read_service_data(self, sub_packet_num):
        self.version = self.comm.read_version()
        self.algo_id = self.comm.read_ub1()
        return None

    def write_service_data(self):
        self.write_header(3)
        self.comm.write_version(self.get_version())
        selected = bytes(self.available_service_ids[i] for i in self.selected_indices)
        self.comm.write_bytes(selected)
        self.comm.write_ub1(1)

    def get_service_data_length(self):
        return 17 + len(self.selected_indices)


class DataIntegrityService(DefaultService):
    def __init__(self, comm):
        super().__init__(comm, 3, NEGO_VERSION, level=0)
        self.algo_id = 0
        self.public_key = None
        self.shared_key = None
        self.iv = None
        self.available_service_names = ["", "MD5", "SHA1", "SHA512", "SHA256", "SHA384"]
        self.available_service_ids = [0, 1, 3, 4, 5, 6]
        self.build_service_list([], True, True)

    def read_service_data(self, sub_packet_num):
        self.version = self.comm.read_version()
        self.algo_id = self.comm.read_ub1()
        return None

    def write_service_data(self):
        self.write_header(2)
        self.comm.write_version(self.get_version())
        selected = bytes(self.available_service_ids[i] for i in self.selected_indices)
        self.comm.write_bytes(selected)

    def get_service_data_length(self):
        return 12 + len(self.selected_indices)


class AdvNego:
    def __init__(self, session, config):
        self.comm = AdvancedNegoComm(session)
        self.session = session
        self.service_list = [None, None, None, None, None]
        self.service_list[1] = AuthService(self.comm)
        self.service_list[2] = EncryptService(self.comm)
        self.service_list[3] = DataIntegrityService(self.comm)
        self.service_list[4] = SupervisorService(self.comm)

    def _read_header(self):
        num = self.session.get_int64(4, False, True)
        if num != DEADBEEF:
            raise ValueError("advanced negotiation error: during receive header")
        length = self.session.get_int(2, False, True)
        version = self.session.get_int(4, False, True)
        count = self.session.get_int(2, False, True)
        err_flags = self.session.get_int(1, False, True)
        return [length, version, count, err_flags]

    def _write_header(self, length, serv_count, err_flags):
        self.session.put_int(DEADBEEF, 4, True, False)
        self.session.put_int(length, 2, True, False)
        self.session.put_int(NEGO_VERSION, 4, True, False)
        self.session.put_int(serv_count, 2, True, False)
        self.session.put_bytes(err_flags)

    def _read_service_header(self):
        service_type = self.session.get_int(2, False, True)
        sub_packet_num = self.session.get_int(2, False, True)
        err = self.session.get_int(4, False, True)
        return [service_type, sub_packet_num, err]

    def read(self):
        self._read_header()
        # for the no-security carrier we only need the header to be valid; each
        # service validates its own response but none installs crypto.
        return None

    def write(self):
        size = 0
        for i in range(1, 5):
            size = size + 8 + self.service_list[i].get_service_data_length()
        self.session.reset_buffer()
        self._write_header(13 + size, 4, 0)
        for i in range(1, 5):
            self.service_list[i].write_service_data()
        return self.session.write()

    def read_full(self):
        """Read and validate the server's advanced-negotiation response."""
        header = self._read_header()
        count = header[2]
        for _ in range(count):
            srv_type, sub_packets, err = self._read_service_header()
            if err != 0:
                raise ValueError("advanced negotiation error: ora-{}".format(err))
            if srv_type == 4:
                self.service_list[4].read_service_data(sub_packets)
            elif srv_type == 1:
                self.service_list[1].read_service_data(sub_packets)
            elif srv_type == 2:
                self.service_list[2].read_service_data(sub_packets)
            elif srv_type == 3:
                self.service_list[3].read_service_data(sub_packets)
        return None

    def start_services(self):
        for i in range(1, 5):
            if self.service_list[i] is not None:
                self.service_list[i].activate_algorithm()
        return None


def write_advanced_nego(session, config):
    """Write the advanced-negotiation request (go-ora advanced_nego.Write)."""
    nego = AdvNego(session, config)
    nego.write()
    nego.read_full()
    nego.start_services()
    return nego

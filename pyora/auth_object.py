"""
O5LOGON / O5AUTH authentication ported from
github.com/sijms/go-ora/v2 auth_object.go
"""

import hashlib
import hmac
import os
import secrets
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def _pkcs5_unpad(data):
    if not data:
        return data
    num = data[-1]
    if num < 16:
        if all(b == num for b in data[len(data) - num:]):
            return data[:len(data) - num]
    return data


def _aes_cbc_encrypt(key, plaintext):
    block = Cipher(algorithms.AES(key), modes.CBC(b"\x00" * 16)).encryptor()
    return block.update(plaintext) + block.finalize()


def _aes_cbc_decrypt(key, ciphertext):
    block = Cipher(algorithms.AES(key), modes.CBC(b"\x00" * 16)).decryptor()
    return block.update(ciphertext) + block.finalize()


def _des_encrypt_block(key, input8):
    from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES  # noqa
    from cryptography.hazmat.primitives.ciphers import Cipher as _C, algorithms as _a, modes as _m
    # single DES (8-byte key)
    block = _C(_a.TripleDES(key * 3), _m.ECB()).encryptor()
    return block.update(input8) + block.finalize()


def generate_speedy_key(buffer, key, turns):
    mac = hmac.new(key, digestmod=hashlib.sha512)
    mac.update(buffer + b"\x00\x00\x00\x01")
    first_hash = bytearray(mac.digest())
    temp_hash = bytearray(first_hash)
    for _ in range(2, turns + 1):
        mac = hmac.new(key, digestmod=hashlib.sha512)
        mac.update(bytes(temp_hash))
        temp_hash = bytearray(mac.digest())
        for i in range(64):
            first_hash[i] ^= temp_hash[i]
    return bytes(first_hash)


def get_key_from_username_and_password(username, password):
    username = username.upper()
    password = password.upper()

    def extend_string(s):
        raw = s.encode("utf-8")
        ret = bytearray(len(raw) * 2)
        for i, c in enumerate(raw):
            ret[i * 2] = 0
            ret[i * 2 + 1] = c
        return bytes(ret)

    buffer = bytearray(extend_string(username) + extend_string(password))
    if len(buffer) % 8:
        buffer.extend(b"\x00" * (8 - len(buffer) % 8))
    key = bytes([1, 35, 69, 103, 137, 171, 205, 239])

    def des_enc(input_, key_):
        ret = bytearray(8)
        for x in range(len(input_) // 8):
            for y in range(8):
                ret[y] ^= input_[x * 8 + y]
            output = _des_encrypt_block(key_, bytes(ret))
            ret = bytearray(output)
        return bytes(ret)

    key1 = des_enc(bytes(buffer), key)
    key2 = des_enc(bytes(buffer), key1)
    return key2 + b"\x00" * 8


def decrypt_session_key(padding, enc_key, session_key):
    result = bytes.fromhex(session_key)
    output = _aes_cbc_decrypt(enc_key, result)
    cut_len = 0
    if padding:
        num = output[-1]
        if num < 16:
            if all(b == num for b in output[len(output) - num:]):
                cut_len = num
    return output[:len(output) - cut_len]


def encrypt_session_key(padding, enc_key, session_key):
    # PKCS5 padding
    block_size = algorithms.AES(enc_key).block_size // 8
    original_len = len(session_key)
    pad = block_size - (len(session_key) % block_size)
    session_key = session_key + bytes([pad]) * pad
    output = _aes_cbc_encrypt(enc_key, session_key)
    if not padding:
        return (output[:original_len]).hex().upper()
    return output.hex().upper()


def encrypt_password(password, key, padding):
    buff1 = os.urandom(0x10)
    buffer = buff1 + password
    return encrypt_session_key(padding, key, buffer)


VERIFIER_5x = 2361
VERIFIER_11g = 6949
VERIFIER_12c = 18453


class AuthObject:
    def __init__(self, username, password, tcp_nego, conn):
        self.e_server_sess_key = ""
        self.e_client_sess_key = ""
        self.e_password = ""
        self.e_speedy_key = ""
        self.server_sess_key = b""
        self.client_sess_key = b""
        self.key_hash = b""
        self.salt = ""
        self.pbkdf2_chk_salt = ""
        self.pbkdf2_vgen_count = 0
        self.pbkdf2_sder_count = 0
        self.global_unique_dbid = ""
        self.use_padding = False
        self.custom_hash = (tcp_nego.server_compile_time_caps[4] & 32) != 0
        self.verifier_type = 0
        self.tcp_nego = tcp_nego
        self._build_trace()
        self._create(username, password, tcp_nego, conn)

    def _build_trace(self):
        pass

    def _create(self, username, password, tcp_nego, conn):
        session = conn.session
        use_padding = False
        loop = True
        while loop:
            message_code = session.get_byte()
            if message_code == 8:
                dict_len = session.get_int(4, True, True)
                for _ in range(dict_len):
                    key, val, num = session.get_key_val()
                    if key == b"AUTH_SESSKEY":
                        if not self.e_server_sess_key:
                            self.e_server_sess_key = val.decode("utf-8")
                    elif key == b"AUTH_VFR_DATA":
                        if not self.salt:
                            self.salt = val.decode("utf-8")
                            self.verifier_type = num
                    elif key == b"AUTH_PBKDF2_CSK_SALT":
                        if not self.pbkdf2_chk_salt:
                            self.pbkdf2_chk_salt = val.decode("utf-8")
                            if len(self.pbkdf2_chk_salt) != 32:
                                from .network.oracle_error import OracleError
                                raise OracleError(28041)
                    elif key == b"AUTH_PBKDF2_VGEN_COUNT":
                        if self.pbkdf2_vgen_count == 0:
                            try:
                                self.pbkdf2_vgen_count = int(val)
                            except ValueError:
                                from .network.oracle_error import OracleError
                                raise OracleError(28041)
                            if self.pbkdf2_vgen_count < 4096 or self.pbkdf2_vgen_count > 100000000:
                                self.pbkdf2_vgen_count = 4096
                    elif key == b"AUTH_PBKDF2_SDER_COUNT":
                        if self.pbkdf2_sder_count == 0:
                            try:
                                self.pbkdf2_sder_count = int(val)
                            except ValueError:
                                from .network.oracle_error import OracleError
                                raise OracleError(28041)
                            if self.pbkdf2_sder_count < 3 or self.pbkdf2_sder_count > 100000000:
                                self.pbkdf2_sder_count = 3
            else:
                conn.process_ttc_response(message_code)
                if message_code == 4:
                    if session.has_error():
                        raise session.get_error()
                    loop = False

        if len(self.e_server_sess_key) != 64 and len(self.e_server_sess_key) != 96:
            raise ValueError("session key should be either 64, 96 bytes long")

        key = None
        speedy_key = None
        padding = False

        if self.verifier_type == VERIFIER_5x:
            key = get_key_from_username_and_password(username, password)
        elif self.verifier_type == VERIFIER_11g:
            if tcp_nego.server_compile_time_caps[4] & 2 == 0:
                padding = True
            salt = bytes.fromhex(self.salt)
            result = password.encode("utf-8") + salt
            key = hashlib.sha1(result).digest()  # 20 bytes
            key = key + b"\x00\x00\x00\x00"  # 24 bytes
        elif self.verifier_type == VERIFIER_12c:
            salt = bytes.fromhex(self.salt)
            message = salt + b"AUTH_PBKDF2_SPEEDY_KEY"
            speedy_key = generate_speedy_key(message, password.encode("utf-8"), self.pbkdf2_vgen_count)
            buffer = speedy_key + salt
            key = hashlib.sha512(buffer).digest()[:32]
        else:
            raise ValueError("unsupported verifier type")

        self.use_padding = padding
        self.server_sess_key = decrypt_session_key(padding, key, self.e_server_sess_key)

        if os.environ.get("PYORA_DEBUG"):
            print("DBG AUTH verifier_type={} padding={} custom_hash={} salt={} esesslen={} srvkeylen={}".format(
                self.verifier_type, padding, self.custom_hash,
                self.salt, len(self.e_server_sess_key), len(self.server_sess_key)),
                file=__import__("sys").stderr)

        self.client_sess_key = bytearray(secrets.token_bytes(len(self.server_sess_key)))
        while bytes(self.client_sess_key) == self.server_sess_key:
            self.client_sess_key = bytearray(secrets.token_bytes(len(self.server_sess_key)))

        self.e_client_sess_key = encrypt_session_key(padding, key, bytes(self.client_sess_key))

        new_key = self.generate_password_enc_key()
        if self.verifier_type == VERIFIER_12c:
            padding = False
        else:
            padding = True
        self.e_password = encrypt_password(password.encode("utf-8"), new_key, True)
        if self.verifier_type == VERIFIER_12c:
            self.e_speedy_key = encrypt_password(speedy_key, new_key, padding)

    # logon modes
    def write(self, conn_option, mode, session):
        keys = []
        values = []
        flags = []

        def append_key_val(k, v, f):
            keys.append(k)
            values.append(v)
            flags.append(f)

        index = 0
        if self.e_client_sess_key:
            append_key_val("AUTH_SESSKEY", self.e_client_sess_key, 1)
            index += 1
        if self.e_password:
            append_key_val("AUTH_PASSWORD", self.e_password, 0)
            index += 1
        if self.e_speedy_key:
            append_key_val("AUTH_PBKDF2_SPEEDY_KEY", self.e_speedy_key, 0)
            index += 1
        append_key_val("AUTH_TERMINAL", conn_option.host_name, 0)
        index += 1
        append_key_val("AUTH_PROGRAM_NM", conn_option.program_name, 0)
        index += 1
        append_key_val("AUTH_MACHINE", conn_option.host_name, 0)
        index += 1
        append_key_val("AUTH_PID", str(conn_option.pid), 0)
        index += 1
        append_key_val("AUTH_SID", conn_option.os_user_name, 0)
        index += 1
        append_key_val("AUTH_CONNECT_STRING", conn_option.connection_data(), 0)
        index += 1
        append_key_val("SESSION_CLIENT_CHARSET", str(self.tcp_nego.server_charset), 0)
        index += 1
        append_key_val("SESSION_CLIENT_LIB_TYPE", "0", 0)
        index += 1
        append_key_val("SESSION_CLIENT_DRIVER_NAME", conn_option.driver_name, 0)
        index += 1
        append_key_val("SESSION_CLIENT_VERSION", "2.0.0.0", 0)
        index += 1
        append_key_val("SESSION_CLIENT_LOBATTR", "1", 0)
        index += 1
        tz = _local_tz_offset()
        alter = ("ALTER SESSION SET NLS_LANGUAGE='{0}' NLS_TERRITORY='{1}'  TIME_ZONE='{2}'\x00"
                 .format(conn_option.language, conn_option.territory, tz))
        append_key_val("AUTH_ALTER_SESSION", alter, 1)
        index += 1
        if conn_option.proxy_client_name:
            append_key_val("PROXY_CLIENT_NAME", conn_option.proxy_client_name, 0)
            index += 1

        session.reset_buffer()
        session.put_bytes(3, 0x73, 0)
        if conn_option.user_id:
            session.put_bytes(1)
            session.put_int(len(conn_option.user_id), 4, True, True)
        else:
            session.put_bytes(0, 0)
        if conn_option.user_id and self.e_password:
            mode |= USER_AND_PASS
        session.put_uint(mode | NO_NEW_PASS, 4, True, True)
        session.put_bytes(1)
        session.put_uint(index, 4, True, True)
        session.put_bytes(1, 1)
        if conn_option.user_id:
            session.put_string(conn_option.user_id)
        for i in range(index):
            session.put_key_val_string(keys[i], values[i], flags[i])
        session.write()

    def generate_password_enc_key(self):
        key1 = self.server_sess_key
        key2 = self.client_sess_key
        start = 16
        logon_compatibility = self.tcp_nego.server_compile_time_caps[4]
        if logon_compatibility & 32:
            ret_key_len = 0
            if self.verifier_type == VERIFIER_5x:
                buffer = bytes(key2[:len(key2) // 2] + key1[:len(key1) // 2])
                key_buffer = buffer.hex().upper()
                ret_key_len = 16
            elif self.verifier_type == VERIFIER_11g:
                buffer = bytes(key2[:24] + key1[:24])
                key_buffer = buffer.hex().upper()
                ret_key_len = 24
            elif self.verifier_type == VERIFIER_12c:
                buffer = bytes(key2 + key1)
                key_buffer = buffer.hex().upper()
                ret_key_len = 32
            else:
                raise ValueError("unsupported verifier type")
            df2key = bytes.fromhex(self.pbkdf2_chk_salt)
            return generate_speedy_key(df2key, key_buffer.encode("utf-8"), self.pbkdf2_sder_count)[:ret_key_len]
        else:
            md5 = hashlib.md5()
            if self.verifier_type == VERIFIER_5x:
                buffer = bytes(key1[x + start] ^ key2[x + start] for x in range(16))
                md5.update(buffer)
                return md5.digest()
            elif self.verifier_type == VERIFIER_11g:
                buffer = bytes(key1[x + start] ^ key2[x + start] for x in range(24))
                md5.update(buffer[:16])
                ret = md5.digest()
                md5 = hashlib.md5()
                md5.update(buffer[16:])
                ret += md5.digest()
                return ret[:24]
            else:
                raise ValueError("unsupported verifier type")


def _local_tz_offset():
    import time
    offset = time.timezone if (time.localtime().tm_isdst == 0) else time.altzone
    offset = -offset  # seconds east of UTC
    if offset == 0:
        return "00:00"
    hours = int(offset // 3600)
    minutes = int((offset // 60) % 60)
    if minutes < 0:
        minutes = -minutes
    return "{:+03d}:{:02d}".format(hours, minutes)


# LogonMode flags
NO_NEW_PASS = 0x1
USER_AND_PASS = 0x100
SYSDBA_MODE = 0x20
SYSOPER_MODE = 0x40

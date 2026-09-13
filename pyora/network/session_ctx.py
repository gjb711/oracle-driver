"""
SessionContext ported from github.com/sijms/go-ora/v2 network/session_ctx.go
"""


class SessionContext:
    def __init__(self, config=None):
        self.sid = None
        self.conn_config = config
        self.version = 317
        self.lo_version = 300
        self.options = 1 | 2048  # 1024 = urgent data transport (OOB)
        self.negotiated_options = 0
        self.our_one = 1
        self.histone = 0
        self.recon_addr = ""
        self.handshake_complete = False
        self.acfl0 = 0
        self.acfl1 = 0
        self.session_data_unit = 0x200000
        self.transport_data_unit = 0x200000
        self.using_async_receivers = False
        self.is_nt_connected = False
        self.on_break_reset = False
        self.got_reset = False
        self.is_redirect = False
        self.advanced_service = AdvancedService()

        if config is not None:
            self.session_data_unit = config.session_data_unit_size
            self.transport_data_unit = config.transport_data_unit_size
            if config.enable_oob:
                self.options |= 1024
        else:
            self.session_data_unit = 0xFFFF
            self.transport_data_unit = 0xFFFF


class AdvancedService:
    """Placeholder for Oracle Network Services (encryption/integrity).

    go-ora wires in CBC/CFB encryption and hash integrity after negotiation.
    This port keeps the negotiated descriptors; when no advanced service is
    active (the default for plain TCP), Encrypt/Decrypt are identity passes.
    """

    def __init__(self):
        self.crypt_algo = None
        self.hash_algo = None
        self.session_key = None
        self.iv = None



def new_session_context(config):
    return SessionContext(config)

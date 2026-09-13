"""
SummaryObject ported from github.com/sijms/go-ora/v2 network/summary_object.go
"""


class BindError:
    def __init__(self):
        self.error_code = 0
        self.row_offset = 0
        self.error_msg = b""


class SummaryObject:
    def __init__(self):
        self.end_of_call_status = 0
        self.end_to_end_ecid_sequence = 0
        self.cur_row_number = 0
        self.ret_code = 0
        self.array_elm_w_error = 0
        self.array_elm_errno = 0
        self.cursor_id = 0
        self.error_pos = 0
        self.sql_type = 0
        self.oer_fatal = 0
        self.flags = 0
        self.user_cursor_opt = 0
        self.upi_param = 0
        self.warning_flag = 0
        self.rba = 0
        self.partition_id = 0
        self.table_id = 0
        self.block_number = 0
        self.slot_number = 0
        self.os_error = 0
        self.stmt_number = 0
        self.call_number = 0
        self.pad1 = 0
        self.success_iter = 0
        self.error_message = None
        self.bind_errors = []


def new_summary(session):
    result = SummaryObject()
    get_int = session.get_int
    get_byte = session.get_byte
    get_dlc = session.get_dlc
    get_clr = session.get_clr

    if session.has_eos_capability:
        result.end_of_call_status = get_int(4, True, True)
    if session.ttc_version >= 3:
        if session.has_fsap_capability:
            result.end_to_end_ecid_sequence = get_int(2, True, True)
    result.cur_row_number = get_int(4, True, True)
    result.ret_code = get_int(2, True, True)
    result.array_elm_w_error = get_int(2, True, True)
    result.array_elm_errno = get_int(2, True, True)
    result.cursor_id = get_int(2, True, True)
    result.error_pos = get_int(2, True, True)
    result.sql_type = get_byte()
    result.oer_fatal = get_byte()
    if session.ttc_version >= 4:
        result.flags = get_int(2, True, True)
        result.user_cursor_opt = get_int(2, True, True)
    else:
        result.flags = get_byte()
        result.user_cursor_opt = get_byte()
    result.upi_param = get_byte()
    result.warning_flag = get_byte()
    result.rba = get_int(4, True, True)
    result.partition_id = get_int(2, True, True)
    result.table_id = get_byte()
    result.block_number = get_int(4, True, True)
    result.slot_number = get_int(2, True, True)
    result.os_error = get_int(4, True, True)
    result.stmt_number = get_byte()
    result.call_number = get_byte()
    result.pad1 = get_int(2, True, True)
    result.success_iter = get_int(4, True, True)

    get_dlc()
    if session.ttc_version < 7:
        get_dlc()
        get_dlc()
        get_dlc()
    else:
        length = get_int(2, True, True)
        if length > 0:
            result.bind_errors = [BindError() for _ in range(length)]
            num = get_byte()
            flag = num == 0xFE
            for x in range(length):
                if flag:
                    if session.use_big_clr_chunks:
                        get_int(4, True, True)
                    else:
                        get_byte()
                result.bind_errors[x].error_code = get_int(2, True, True)
            if flag:
                get_byte()
        length = get_int(4, True, True)
        if length > 0:
            if not result.bind_errors:
                result.bind_errors = [BindError() for _ in range(length)]
            num = get_byte()
            flag = num == 0xFE
            for x in range(length):
                if flag:
                    if session.use_big_clr_chunks:
                        get_int(4, True, True)
                    else:
                        get_byte()
                result.bind_errors[x].row_offset = get_int(4, True, True)
            if flag:
                get_byte()
        length = get_int(2, True, True)
        if length > 0:
            if not result.bind_errors:
                result.bind_errors = [BindError() for _ in range(length)]
            get_byte()
            for x in range(length):
                get_int(2, True, True)
                result.bind_errors[x].error_msg = get_dlc()
                get_byte()
                get_byte()
        if session.ttc_version >= 7:
            result.ret_code = get_int(4, True, True)
            result.cur_row_number = get_int(8, True, True)

    if result.ret_code != 0:
        # error message is a CLR (1-byte length prefix), not a DLC (4-byte
        # compressed int prefix); go-ora uses session.GetClr() here.
        result.error_message = get_clr()
    if result.bind_errors and result.ret_code == 24381:
        result.ret_code = result.bind_errors[0].error_code
        result.error_message = result.bind_errors[0].error_msg
    return result

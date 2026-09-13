"""
OracleError ported from github.com/sijms/go-ora/v2 network/oracle_error.go
"""


class OracleError(Exception):
    def __init__(self, err_code=0, err_msg="", err_pos=-1):
        super().__init__(err_msg)
        self.err_code = err_code
        self.err_msg = err_msg
        self.err_pos = err_pos

    def translate(self):
        """Fill in a human-readable message for a known error code."""
        if self.err_code == 0 and self.err_msg:
            return
        mapping = {
            1: "ORA-00001: Unique constraint violation",
            900: "ORA-00900: Invalid SQL statement",
            901: "ORA-00901: Invalid CREATE command",
            902: "ORA-00902: Invalid data type",
            903: "ORA-00903: Invalid table name",
            904: "ORA-00904: Invalid identifier",
            905: "ORA-00905: Misspelled keyword",
            906: "ORA-00906: Missing left parenthesis",
            907: "ORA-00907: Missing right parenthesis",
            1001: "ORA-01001: invalid cursor",
            1013: "ORA-01013: user requested cancel of current operation",
            12631: "ORA-12631: Username retrieval failed",
            12564: "ORA-12564: TNS connection refused",
            12506: "ORA-12506: TNS:listener rejected connection based on service ACL filtering",
            12514: "ORA-12514: TNS:listener does not currently know of service requested in connect descriptor",
            12516: "ORA-12516: TNS:listener could not find available handler with matching protocol stack",
            3135: "ORA-03135: connection lost contact",
            28041: "ORA-28041: Authentication protocol internal error",
        }
        if self.err_code in mapping:
            self.err_msg = mapping[self.err_code]
        else:
            self.err_msg = "ORA-{}".format(self.err_code)

    @property
    def message(self):
        return self.str()

    def str(self):
        if not self.err_msg:
            self.translate()
        if self.err_pos >= 0:
            return "{} error occur at position: {}".format(self.err_msg, self.err_pos)
        return self.err_msg

    def __str__(self):
        return self.str()

    def bad(self):
        return self.err_code in (28, 1001, 1012, 1033, 1034, 1089, 3113, 3114, 3135, 12528, 12537)


def new_oracle_error(err_code):
    return OracleError(err_code=err_code, err_pos=-1)


class ErrConnReset(Exception):
    """Connection break due to context timeout."""

    def __init__(self, *args):
        super().__init__(*args or ("connection break due to context timeout",))

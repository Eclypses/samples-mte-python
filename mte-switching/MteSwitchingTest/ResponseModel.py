#!/usr/bin/env python3

from Constants import Constants

class ResponseModel:
    def __init__(self):

        # The data.
        self.data = ""

        # The success state.
        self.success = True

        # The message.
        self.message = ""

        # The result code.
        self.result_code = Constants().RC_SUCCESS

        # Exception id.
        self.exception_uid = ""

        # The date/time offset for when the JWT token expires.
        self.token_expires_in = 60

        # The access token.
        self.access_token = ""
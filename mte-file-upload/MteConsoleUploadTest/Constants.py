#!/usr/bin/env python3

import json

class Constants:
    def __init__(self):
        # MTE Client ID header.
        self.CLIENT_ID_HEADER = "x-client-id"

        # Use this when running locally.
        self.REST_API_NAME = "http://localhost:52603"
        # Use this when running against Eclypses API.
        #REST_API_NAME = "https://dev-echo.eclypses.com"

        self.JSON_CONTENT_TYPE = "application/json"
        self.TEXT_CONTENT_TYPE = "text/plain"

        # Set up Json to be not case sensitive.
        # todo maybe case sensitive stuff?

        # Misc result codes.
        self.STR_SUCCESS = "SUCCESS"
        self.RC_SUCCESS = "000"
        self.RC_VALIDATION_ERROR = "100"
        self.RC_MTE_ENCODE_EXCEPTION = "110"
        self.RC_MTE_DECODE_EXCEPTION = "120"
        self.RC_MTE_STATE_CREATION = "130"
        self.RC_MTE_STATE_RETRIEVAL = "131"
        self.RC_MTE_STATE_SAVE = "132"
        self.RC_MTE_STATE_NOT_FOUND = "133"
        self.RC_INVALID_NONCE = "140"

        self.RC_HTTP_ERROR = "300"
        self.RC_UPLOAD_EXCEPTION = "301"
        self.RC_HANDSHAKE_EXCEPTION = "302"
        self.RC_LOGIN_EXCEPTION = "303"
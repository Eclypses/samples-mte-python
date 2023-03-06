#!/usr/bin/env python3

class LoginResponse:
    def __init__(self):
        # Login message received from server.
        self.login_message = ""

        # Current Encoder state after login.
        self.encoder_state = ""

        # Current Decoder state after login.
        self.decoder_state = ""
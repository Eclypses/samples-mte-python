#!/usr/bin/env python3

class HandshakeResponse:
    def __init__(self):
        # Holds the current Encoder state.
        self.encoder_state = ""

        # Holds the current decoder state.
        self.decoder_state = ""
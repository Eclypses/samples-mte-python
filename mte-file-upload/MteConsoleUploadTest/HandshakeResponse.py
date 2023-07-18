#!/usr/bin/env python3

class HandshakeResponse:
    def __init__(self):
        # Holds the current Encoder state.
        self.encoder_state = ""

        # Holds the current Decoder state.
        self.decoder_state = ""

        # Holds the max DRBG reseed interval.
        self.max_seed = 0

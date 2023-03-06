#!/usr/bin/env python3

class UploadResponse:
    def __init__(self):
        # Response from Server after upload.
        self.server_response = ""

        # Current Encoder state after upload.
        self.encoder_state = ""

        # Current Decoder state after upload.
        self.decoder_state = ""

        # Current seed count.
        self.current_seed = 0

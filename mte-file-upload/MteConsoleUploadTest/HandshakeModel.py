#!/usr/bin/env python3

class HandshakeModel:
    def __init__(self):
        # Calculated on the server, sent back to the client
        # and used for Nonce.
        self.timestamp = ""

        # Session identifier determined by the client
        # used as PK for storing the MTE state as well
        # as looking up the shared secret.
        self.conversation_identifier = ""

        # Diffie-Hellman public key of the client Encoder.
        # This should be used for server Decoder.
        self.client_encoder_public_key = ""

        # Diffie-Hellman public key of the client Decoder.
        # This should be used for server Encoder.
        self.client_decoder_public_key = ""

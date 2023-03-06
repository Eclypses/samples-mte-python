#!/usr/bin/env python3
from typing import List
from MteJail import MteJail

class Cbs(MteJail):
    def __init__(self):
        super().__init__()

    def nonce_callback(self, min_length: int, max_length: int, nonce: bytearray, n_bytes: List[int]) -> None:

        # Super.
        super().nonce_callback(min_length, max_length, nonce, n_bytes)
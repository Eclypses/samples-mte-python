#!/usr/bin/env python3

from typing import Tuple
from MteJail import MteJail
from MteBase import MteBase
from MteEnc import MteEnc
from MteStatus import MteStatus
from Cbs import Cbs

class EncoderDevice:
    def call_encoder_device(self, jail_algorithm: MteJail.Algo, input: str, nonce: int, personal: str) -> Tuple[MteStatus, str]:
        encoded_message = ""

        # Initialize MTE license. If a license code is not required (e.g., trial
        # mode), this can be skipped.
        base_obj = MteBase()
        if base_obj.init_license("YOUR_COMPANY", "YOUR_LICENSE") == False:
            status = MteStatus.mte_status_license_error
            print ("License initialization error ({0}: {1})".format(base_obj.get_status_name(status), base_obj.get_status_description()))
            return (status, "")

        # Output original data.
        print ("Original data: {0}".format(input))

        # Create the Encoder.
        encoder = MteEnc.fromdefault()

        # Crete all-zero entropy for this demo. The nonce will also be set to 0.
        # This should never be done in real applications.
        entropy_bytes = encoder.get_drbgs_entropy_min_bytes(encoder.get_drbg())
        entropy = bytearray(entropy_bytes)

        # Instantiate the Encoder.
        encoder.set_entropy(entropy)

        # Jailbreak callback.
        cb = Cbs()        
        cb.set_algo(jail_algorithm)
        cb.set_nonce_seed(nonce)
        encoder.set_nonce_callback(cb)

        status = encoder.instantiate(personal)
        if status != MteStatus.mte_status_success:
            print("Encoder instantiate error ({0}: {1})".format(encoder.get_status_name(status), encoder.get_status_description(status)))
            return (status, "")

        # Encode the input.
        encoded_message, status = encoder.encode_b64(input)
        if status != MteStatus.mte_status_success:
            print("Encode error ({0}: {1})".format(encoder.get_status_name(status), encoder.get_status_description(status)))
            return (status, "")

        # Return success.
        return (status, encoded_message)
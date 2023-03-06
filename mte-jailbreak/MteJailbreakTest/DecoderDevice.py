#!/usr/bin/env python3

from typing import Tuple
from MteJail import MteJail
from MteBase import MteBase
from MteDec import MteDec
from MteStatus import MteStatus
from Cbs import Cbs

class DecoderDevice:
    def call_decoder_device(self, jail_algorithm: MteJail.Algo, encoded_input: str, nonce: int, personal: str) -> Tuple[MteStatus, str]:
        # Default return string to empty
        decoded_message = ""

        # Initialize MTE license. If a license code is not required (e.g., trial
        # mode), this can be skipped.
        base_obj = MteBase()
        if base_obj.init_license("YOUR_COMPANY", "YOUR_LICENSE") == False:
            status = MteStatus.mte_status_license_error
            print ("License initialization error ({0}: {1})".format(base_obj.get_status_name(status), base_obj.get_status_description()))
            return (status, "")

        # Output original data.
        print ("Original data: {0}".format(input))

        # Create default Decoder.
        decoder = MteDec.fromdefault()

        # Crete all-zero entropy for this demo. The nonce will also be set to 0.
        # This should never be done in real applications.
        entropy_bytes = decoder.get_drbgs_entropy_min_bytes(decoder.get_drbg())
        entropy = bytearray(entropy_bytes)

        # Instantiate the Decoder.
        decoder.set_entropy(entropy)

        # Set the device type and nonce seed.
        # Use the jailbreak nonce callback.
        cb = Cbs()
        cb.set_algo(jail_algorithm)
        cb.set_nonce_seed(nonce)
        decoder.set_nonce_callback(cb)

        status = decoder.instantiate(personal)
        if status != MteStatus.mte_status_success:
            print("Decoder instantiate error ({0}: {1})".format(decoder.get_status_name(status), decoder.get_status_description(status)))
            return (status, "")

        # Decode the message.
        decoded_message, status = decoder.decode_str_b64(encoded_input)
        if decoder.status_is_error(status):
            print("Decode error ({0}: {1})".format(decoder.get_status_name(status), decoder.get_status_description(status)))
            return (status, "")

        return (status, decoded_message)






    

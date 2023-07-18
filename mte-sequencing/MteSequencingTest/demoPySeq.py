# THIS SOFTWARE MAY NOT BE USED FOR PRODUCTION. Otherwise,
# The MIT License (MIT)
#
# Copyright (c) Eclypses, Inc.
#
# All rights reserved.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#!/usr/bin/env python3

import sys
from MteBase import MteBase
from MteEnc import MteEnc
from MteDec import MteDec
from MteStatus import MteStatus

def main():
    # Status.
    status = MteStatus.mte_status_success

    # Inputs.
    inputs = ["message 0", "message 1", "message 2", "message 3"]

    # Personalization string.
    personal = "demo"

    # Initialize MTE license. If a license code is not required (e.g., trial
    # mode), this can be skipped.
    if  MteBase.init_license("YOUR_COMPANY", "YOUR_LICENSE") == False:
        status = MteStatus.mte_status_license_error
        print ("License init error ({0}): {1}".format(MteBase.get_status_name(status), MteBase.get_status_description(status)))
        return status

    # Create the Encoder.
    encoder = MteEnc.fromdefault()

    # Create all-zero entropy for this demo. The nonce will also be set to 0.
    # This should never be done in real applications.
    entropy_bytes = MteBase.get_drbgs_entropy_min_bytes(encoder.get_drbg())
    entropy = bytearray(entropy_bytes)

    # Instantiate the Encoder.
    encoder.set_entropy(entropy)
    encoder.set_nonce(0)
    status = encoder.instantiate(personal)
    if status != MteStatus.mte_status_success:
        print ("Encoder instantiate error ({0}): {1}".format(encoder.get_status_name(status), encoder.get_status_description(status)))
        return status

    # Encode the inputs.
    encodings = []
    for i in range(len(inputs)):
        encoding, status = encoder.encode_b64(inputs[i])
        encodings.append(encoding)
        if status != MteStatus.mte_status_success:
            print ("Encode error ({0}): {1}".format(encoder.get_status_name(status), encoder.get_status_description(status)))
            return status
        print ("Encode #{0}: {1} -> {2}".format(i, inputs[i], encodings[i]))

    # Create Decoder with different sequence windows.
    decoder_v = MteDec.fromdefault()
    decoder_f = MteDec.fromdefault(0, 2)
    decoder_a = MteDec.fromdefault(0, -2)

    # Instantiate the Decoders.
    decoder_v.set_entropy(entropy)
    decoder_v.set_nonce(0)
    status = decoder_v.instantiate(personal)
    if status == MteStatus.mte_status_success:
        decoder_f.set_entropy(entropy)
        decoder_f.set_nonce(0)
        status = decoder_f.instantiate(personal)
        if status == MteStatus.mte_status_success:
            decoder_a.set_entropy(entropy)
            decoder_a.set_nonce(0)
            status = decoder_a.instantiate(personal)

    if status != MteStatus.mte_status_success:
        print ("Decoder instantiate error ({0}): {1}".format(decoder_v.get_status_name(status), decoder_v.get_status_description(status)))
        return status

    # Save the async Decoder state.
    d_saved = decoder_a.save_state()

    # Create the corrupt version of message #2.
    first = ord(encodings[2][0]) + 1
    corrupt = chr(first) + encodings[2][1:]
    
    # Decode in verification-only mode.
    print ("\nVerification-only mode (sequence window = 0):")
    decoded, status = decoder_v.decode_str_b64(encodings[0])
    print ("Decode #0: {0}, {1}".format(decoder_v.get_status_name(status), decoded))
    decoded, status = decoder_v.decode_str_b64(encodings[0])
    print ("Decode #0: {0}, {1}".format(decoder_v.get_status_name(status), decoded))
    decoded, status = decoder_v.decode_str_b64(encodings[2])
    print ("Decode #2: {0}, {1}".format(decoder_v.get_status_name(status), decoded))
    decoded, status = decoder_v.decode_str_b64(encodings[1])
    print ("Decode #1: {0}, {1}".format(decoder_v.get_status_name(status), decoded))
    decoded, status = decoder_v.decode_str_b64(encodings[2])
    print ("Decode #2: {0}, {1}".format(decoder_v.get_status_name(status), decoded))
    decoded, status = decoder_v.decode_str_b64(encodings[3])
    print ("Decode #3: {0}, {1}".format(decoder_v.get_status_name(status), decoded))

    # Decode in forward-only mode.
    print ("\nForward-only mode (sequence window = 2):")
    decoded, status = decoder_f.decode_str_b64(encodings[0])
    print ("Decode #0: {0}, {1}".format(decoder_f.get_status_name(status), decoded))
    decoded, status = decoder_f.decode_str_b64(encodings[0])
    print ("Decode #0: {0}, {1}".format(decoder_f.get_status_name(status), decoded))
    decoded, status = decoder_f.decode_str_b64(corrupt)
    print ("Corrupt #2: {0}, {1}".format(decoder_f.get_status_name(status), decoded))
    decoded, status = decoder_f.decode_str_b64(encodings[2])
    print ("Decode #2: {0}, {1}".format(decoder_f.get_status_name(status), decoded))
    decoded, status = decoder_f.decode_str_b64(encodings[1])
    print ("Decode #1: {0}, {1}".format(decoder_f.get_status_name(status), decoded))
    decoded, status = decoder_f.decode_str_b64(encodings[2])
    print ("Decode #2: {0}, {1}".format(decoder_f.get_status_name(status), decoded))
    decoded, status = decoder_f.decode_str_b64(encodings[3])
    print ("Decode #3: {0}, {1}".format(decoder_f.get_status_name(status), decoded))

    # Decode in async mode.
    print ("\nAsync mode (sequence window = -2):")
    decoded, status = decoder_a.decode_str_b64(encodings[0])
    print ("Decode #0: {0}, {1}".format(decoder_a.get_status_name(status), decoded))
    decoded, status = decoder_a.decode_str_b64(encodings[0])
    print ("Decode #0: {0}, {1}".format(decoder_a.get_status_name(status), decoded))
    decoded, status = decoder_a.decode_str_b64(corrupt)
    print ("Corrupt #2: {0}, {1}".format(decoder_a.get_status_name(status), decoded))
    decoded, status = decoder_a.decode_str_b64(encodings[2])
    print ("Decode #2: {0}, {1}".format(decoder_a.get_status_name(status), decoded))
    decoded, status = decoder_a.decode_str_b64(encodings[2])
    print ("Decode #2: {0}, {1}".format(decoder_a.get_status_name(status), decoded))
    decoded, status = decoder_a.decode_str_b64(encodings[1])
    print ("Decode #1: {0}, {1}".format(decoder_a.get_status_name(status), decoded))
    decoded, status = decoder_a.decode_str_b64(encodings[2])
    print ("Decode #2: {0}, {1}".format(decoder_a.get_status_name(status), decoded))
    decoded, status = decoder_a.decode_str_b64(encodings[3])
    print ("Decode #3: {0}, {1}".format(decoder_a.get_status_name(status), decoded))

    # Restore and decode again in a different order.
    decoder_a.restore_state(d_saved)
    print ("\nAsync mode (sequence window = -2):")
    decoded, status = decoder_a.decode_str_b64(encodings[3])
    print ("Decode #3: {0}, {1}".format(decoder_a.get_status_name(status), decoded))
    decoded, status = decoder_a.decode_str_b64(encodings[0])
    print ("Decode #0: {0}, {1}".format(decoder_a.get_status_name(status), decoded))
    decoded, status = decoder_a.decode_str_b64(encodings[2])
    print ("Decode #2: {0}, {1}".format(decoder_a.get_status_name(status), decoded))
    decoded, status = decoder_a.decode_str_b64(encodings[1])
    print ("Decode #1: {0}, {1}".format(decoder_a.get_status_name(status), decoded))
   
    # Success.
    return 0

if __name__ == "__main__":
    sys.exit(main())

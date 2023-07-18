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
from EncoderDevice import EncoderDevice
from DecoderDevice import DecoderDevice
from MteBase import MteBase
from MteJail import MteJail
from MteStatus import MteStatus

def main():
    # Status.
    status = MteStatus.mte_status_success

    # Input.
    input = "hello"

    # Personalization string.
    personal = "demo"

    mte_jail_algorithm : MteJail.Algo

    # Set nonce.
    nonce : int = 123
    times_to_run = 2

    for i in range(times_to_run):
        # Use none for first time;
        # all other times use different algorithm.
        mte_jail_algorithm = MteJail.Algo.a_none if i == 0 else MteJail.Algo.a_ios_x86_64_sim

        # Call Encoder device.
        encoder = EncoderDevice()
        encoder_status, encoded_message = encoder.call_encoder_device(jail_algorithm=mte_jail_algorithm, input=input, nonce=nonce, personal=personal)
        if encoder_status != MteStatus.mte_status_success:
            # There was an error, end.
            return encoder_status

        # Display the message.
        print ("Base64 message: {0}".format(encoded_message))

        decoder = DecoderDevice()
        status, decoded_message = decoder.call_decoder_device(jail_algorithm=mte_jail_algorithm, encoded_input=encoded_message, nonce=nonce, personal=personal)
        if status != MteStatus.mte_status_success:
            # If this specific error happens after first run
            # we know the Encoder device has been jail broken.
            if status == MteStatus.mte_status_token_does_not_exist and i > 0:
                print ("Paired device has been compromised, possible jail broken device.")
                return -1

            print ("Decode warning ({0}: {1})".format(MteBase.get_status_name(status), MteBase.get_status_description(status)))

        # Output the decoded data.
        print ("Decoded data: {0}".format(decoded_message))

        # Compare the decoded data against the original data.
        if decoded_message == input:
            print ("The original data and decoded data match.")
        else:
            print ("The original data and decoded data DO NOT match.")

    print ("Complete, press enter to end...")
    #_ = input()

    # Success.
    return 0

if __name__ == "__main__":
    sys.exit(main())
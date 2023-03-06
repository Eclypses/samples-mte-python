#!/usr/bin/env python3

import sys
import uuid
from asyncio.windows_events import NULL
from tkinter import filedialog as fd, Tk as tk
from HandshakeResponse import HandshakeResponse
from UploadFile import UploadFile
from MteMkeEnc import MteMkeEnc
from MteMkeDec import MteMkeDec

# Create default Encoder and Decoder.
client_encoder = MteMkeEnc.fromdefault()
client_decoder = MteMkeDec.fromdefault()

# Set if using MTE.
use_mte = True

max_seed = 0
reseed_percentage = 0.90

def main():

    # Initialize Encoder and Decoder and set client_id.
    handshake = HandshakeResponse()
    handshake.encoder_state = ""
    handshake.decoder_state = ""

    client_id = str(uuid.uuid4())

    # Handshake with server and create MTE.
    handshake_response = UploadFile().handshake_with_server(client_id)
    if not handshake_response.success:
        raise Exception("Error trying to handshake with server: {0}\n".format(
            handshake_response.message))

    # Set the max_seed interval
    max_seed = handshake_response.data.max_seed

    # Set Decoder and Encoder state.
    handshake.decoder_state = handshake_response.data.decoder_state
    handshake.encoder_state = handshake_response.data.encoder_state

    # Allow file upload until user selects to end.
    while True:
        # Prompt user for file to upload.
        path = ""

        try:
            # Fix foregrounding window issue
            dialog = tk()
            dialog.withdraw()
            dialog.wm_attributes('-topmost', 1)
            path = fd.askopenfilename(parent=dialog)
        finally:
            dialog.destroy()

        # If the path is empty, the dialog was cancelled.
        if not path:
            break

        # Send file to server.
        upload_response = UploadFile().send(
            path, use_mte, handshake.encoder_state, handshake.decoder_state, client_id)

        # If unsuccessful, then end.
        if not upload_response.success:
            raise Exception("Error uploading file: {0}\n".format(
                upload_response.message))       

        # Check current seed life.
        if upload_response.data.current_seed > (max_seed * reseed_percentage):
            handshake_response = UploadFile().handshake_with_server(client_id)
            if not handshake_response.success:
                raise Exception("Error trying to handshake to reseed MTE: {0}\n".format(
                    handshake_response.message))
            
            # Update Encoder and Decoder states to be latest version.
            handshake.encoder_state = handshake_response.data.encoder_state
            handshake.decoder_state = handshake_response.data.decoder_state
            
        else:
            # Update Encoder and Decoder states to be latest version.
            handshake.encoder_state = upload_response.data.encoder_state
            handshake.decoder_state = upload_response.data.decoder_state

        print(upload_response.data.server_response)

        # Prompt to upload another file.
        print("Would you like to upload an additional file (y/n)?")
        send_additional = input()
        if send_additional != NULL and send_additional.lower().startswith("n"):
            break

    return 0

if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3

import sys
import uuid
from asyncio.windows_events import NULL
from tkinter import filedialog as fd, Tk as tk
from HandshakeResponse import HandshakeResponse
from ResponseModel import ResponseModel
from UploadFile import UploadFile
from MteMkeEnc import MteMkeEnc
from MteMkeDec import MteMkeDec

# Create default Encoder and Decoder.
client_encoder = MteMkeEnc.fromdefault()
client_decoder = MteMkeDec.fromdefault()

# Set if using MTE.
use_mte = True

def main():

    # Initialize Encoder and Decoder and set client_id.
    handshake = HandshakeResponse()
    handshake.encoder_state = ""
    handshake.decoder_state = ""

    client_id = str(uuid.uuid4())

    # Handshake with server and create MTE.
    handshake_response: ResponseModel = UploadFile().handshake_with_server(client_id)
    if not handshake_response.success:
        raise Exception("Error trying to handshake with server: {0}\n".format(
            handshake_response.message))

    # Set Decoder and Encoder state.
    handshake.decoder_state = handshake_response.data.decoder_state
    handshake.encoder_state = handshake_response.data.encoder_state
    print ("En: {0}".format(handshake.encoder_state))
    print ("De: {0}".format(handshake.decoder_state))

    login_response = UploadFile().login_to_server(client_id, handshake.encoder_state, handshake.decoder_state)
    if login_response.success == False:
        raise Exception("Error trying to login: {0}".format(login_response.message))

    # Set Decoder and Encoder state.
    handshake.decoder_state = login_response.data.decoder_state
    handshake.encoder_state = login_response.data.encoder_state

    # Set the jwt.
    jwt = login_response.access_token 

    # Allow file upload until user selects to end.
    while True:
        # Prompt user for file to upload.
        path = ""

        try:
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
            path, use_mte, handshake.encoder_state, handshake.decoder_state, client_id, jwt)

        # If unsuccessful, then end.
        if not upload_response.success:
            raise Exception("Error uploading file: {0}\n".format(
                upload_response.message))

        print(upload_response.data.server_response)

        # Update the jwt.
        jwt = upload_response.access_token

        # Update Encoder and Decoder states to be the latest state.
        handshake.encoder_state = upload_response.data.encoder_state
        handshake.decoder_state = upload_response.data.decoder_state

        # Prompt to upload another file.
        print("Would you like to upload an additional file (y/n)?")
        send_additional = input()
        if send_additional != NULL and send_additional.lower().startswith("n"):
            break

    return 0

if __name__ == "__main__":
    sys.exit(main())

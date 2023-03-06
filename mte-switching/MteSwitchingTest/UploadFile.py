#!/usr/bin/env python3

import requests
import json
import os
import base64
import uuid
from asyncio.windows_events import NULL
from Constants import Constants
from HandshakeModel import HandshakeModel
from ResponseModel import ResponseModel
from HandshakeResponse import HandshakeResponse
from UploadResponse import UploadResponse
from EclypsesECDH import EclypsesECDH
from LoginModel import LoginModel
from LoginResponse import LoginResponse
from MteEnc import MteEnc
from MteDec import MteDec
from MteMkeEnc import MteMkeEnc
from MteMkeDec import MteMkeDec
from MteStatus import MteStatus

class UploadFile:
    def __init__(self):
        # Set upload file constants.
        self.MAX_CHUNK_SIZE = 1024

        # Upload file properties.
        self.web_request = ""
        self.file_reader = ""
        self.request_stream = ""

        self.max_reseed_interval = 0
        self.reseed_percentage = 0.90

    def handshake_with_server(self, client_id: str) -> ResponseModel:
        """
        Handshakes with the server.
        """
        response = ResponseModel()

        # Create client_id for this client.
        handshake = HandshakeModel()
        handshake.conversation_identifier = client_id

        # Create Eclypses DH containers for handshake.
        encoder_ecdh = EclypsesECDH()
        decoder_ecdh = EclypsesECDH()

        # Get the public key to send to other side.
        handshake.client_encoder_public_key = encoder_ecdh.get_device_public_key()
        handshake.client_decoder_public_key = decoder_ecdh.get_device_public_key()

        # Perform handshake.
        url = Constants().REST_API_NAME + "/api/handshake"
        payload = {
            "Timestamp": "null",
            "ConversationIdentifier": handshake.conversation_identifier,
            "ClientEncoderPublicKey": handshake.client_encoder_public_key.decode(),
            "ClientDecoderPublicKey": handshake.client_decoder_public_key.decode()
        }
        headers = {
            "Content-Type": "application/json",
            "accept": "*/*",
            Constants().CLIENT_ID_HEADER: handshake.conversation_identifier
        }
        api_handshake_response = requests.post(
            url=url, data=json.dumps(payload), headers=headers)

        # Deserialize the result from handshake.
        server_response = api_handshake_response.json()

        # If handshake was not successful, then break.
        if server_response['Success'] == False:
            print("Error making DH handshake for Client {0}: {1}".format(
                  client_id, server_response['Message']))
            response.data = server_response['Data']
            response.message = server_response['Message']
            response.success = server_response['Success']
            response.result_code = server_response['ResultCode']
            response.access_token = server_response['access_token']
            response.exception_uid = server_response['ExceptionUid']
            return response

        # Create shared secret.
        encoder_shared_secret_model = encoder_ecdh.create_shared_secret(
            bytes(server_response['Data']['ClientEncoderPublicKey'], 'utf-8'))
        decoder_shared_secret_model = decoder_ecdh.create_shared_secret(
            bytes(server_response['Data']['ClientDecoderPublicKey'], 'utf-8'))

        # Set MTE settings and get state.

        # Get the nonce from the timestamp.
        nonce = int(server_response['Data']['Timestamp'])

        response.data = HandshakeResponse()

        # Set Encoder and then save state.
        encoder = MteMkeEnc.fromdefault()
        encoder.set_entropy(base64.b64decode(encoder_shared_secret_model))
        encoder.set_nonce(nonce)
        status = encoder.instantiate(handshake.conversation_identifier)
        if status != MteStatus.mte_status_success:
            response.success = False
            response.message = "Failed to initialize the MTE Encoder engine. Status {0} / {1}".format(
                encoder.get_status_name(status), encoder.get_status_description(status))
            response.result_code = Constants().RC_MTE_STATE_CREATION
            return response
        response.data.encoder_state = encoder.save_state_b64()

        self.max_reseed_interval = encoder.get_drbgs_reseed_interval(encoder.get_drbg())
        
        # Set Decoder and then save state.
        decoder = MteMkeDec.fromdefault()
        decoder.set_entropy(base64.b64decode(decoder_shared_secret_model))
        decoder.set_nonce(nonce)
        status = decoder.instantiate(handshake.conversation_identifier)
        if status != MteStatus.mte_status_success:
            response.success = False
            response.message = "Failed to initialize the MTE Decoder engine. Status {0} / {1}".format(
                decoder.get_status_name(status), decoder.get_status_description(status))
            response.result_code = Constants().RC_MTE_STATE_CREATION
            return response
        response.data.decoder_state = decoder.save_state_b64()
        return response

    def send(self, path: str, use_mte: bool, encoder_state: str, decoder_state:str, client_id:str, auth_header:str) -> ResponseModel:
        """
        Sends the file up to the server.
        """
        upload_response = ResponseModel()
        upload_response.data = UploadResponse()
        upload_response.data.encoder_state = encoder_state
        upload_response.data.decoder_state = decoder_state

        # Create default Encoder.
        encoder = MteMkeEnc.fromdefault()

        # Get file info and create url.
        url_type = "mte" if use_mte else "nomte"
        file_url = os.path.join(Constants().REST_API_NAME + "/FileUploadLogin/",
            url_type + "?name=" + os.path.basename(path))

        # Create file stream and array.
        file_reader = open(path, 'rb')
        web_request = bytearray()

        # Get size of file by reading the bytes.
        file_size = 0
        while True:
            file_bytes = file_reader.read(UploadFile().MAX_CHUNK_SIZE)
            file_size += len(file_bytes)
            if len(file_bytes) == 0:
                break
        file_reader.close()

        content_length = file_size
        if use_mte:
            # If we are using the MTE, adjust the content length.
            content_length += encoder.encrypt_finish_bytes()

        remaining_bytes = file_size
        number_of_bytes_read = 0

        if auth_header != NULL and len(auth_header) > 0:
            if auth_header.startswith("Bearer") == False:
                auth_header = "Bearer " + auth_header
         
        if use_mte:
            # Restore Encoder from state.
            status = encoder.restore_state_b64(encoder_state)
            if status != MteStatus.mte_status_success:
                upload_response.success = False
                upload_response.result_code = Constants().RC_MTE_STATE_RETRIEVAL
                upload_response.message = "Failed to restore MTE Encoder engine. Status: {0} / {1}".format(
                    encoder.get_status_name(status), encoder.get_status_description(status))
                return upload_response

            # Start the chunking session.
            status = encoder.start_encrypt()
            if status != MteStatus.mte_status_success:
                upload_response.success = False
                upload_response.result_code = Constants().RC_MTE_ENCODE_EXCEPTION
                upload_response.message = "Failed to start encode chunk. Status: {0} / {1}".format(
                    encoder.get_status_name(status), encoder.get_status_description(status))
                return upload_response

        file_reader = open(path, 'rb')
        # Read all bytes from the file.
        while number_of_bytes_read < file_size:
            file_bytes = file_reader.read(UploadFile().MAX_CHUNK_SIZE)

            if use_mte:
                # Encode the data in place - encoded data is put back in place in the buffer.
                chunk_status = encoder.encrypt_chunk(file_bytes)
                if chunk_status != MteStatus.mte_status_success:
                    upload_response.success = False
                    upload_response.result_code = Constants().RC_MTE_ENCODE_EXCEPTION
                    upload_response.message = "Failed to encode chunk. Status: {0} / {1}".format(
                        encoder.get_status_name(chunk_status), encoder.get_status_description(chunk_status))
                    return upload_response

            # Write the data to the array.
            if len(file_bytes) > 0:
                web_request.extend(file_bytes)
            number_of_bytes_read += len(file_bytes)
            remaining_bytes -= len(file_bytes)

        if use_mte:
            # Finish the chunking session.
            final_encoded_chunk, finish_status = encoder.finish_encrypt()
            if finish_status != MteStatus.mte_status_success:
                upload_response.success = False
                upload_response.result_code = Constants().RC_MTE_ENCODE_EXCEPTION
                upload_response.message = "Failed to finish encode chunk. Status: {0} / {1}".format(
                    encoder.get_status_name(finish_status), encoder.get_status_description(finish_status))
                return upload_response

            # Append the final data to the array.
            if len(final_encoded_chunk) > 0:
                web_request.extend(final_encoded_chunk)

            # Check the Re-seed Interval.
            current_seed = encoder.get_reseed_counter()
            self.max_reseed_interval = encoder.get_drbgs_reseed_interval(encoder.get_drbg())

            # Save the Encoder state.
            upload_response.data.encoder_state = encoder.save_state_b64()

        # Get the response.
        headers = {
            "Content-Type": "application/json",
            "accept": "*/*",
            "Content-Length": str(content_length),
            Constants().CLIENT_ID_HEADER: client_id,
            "Authorization": auth_header
        }

        api_handshake_response = requests.post(
            url=file_url, data=web_request, headers=headers)

        text_response = api_handshake_response.json()

        # Get the return text.
        if text_response['Success'] == False:
            # Check if we need to re-handshake.
            if text_response['ResultCode'] == Constants().RC_MTE_STATE_NOT_FOUND:
                # The server does not have this client's state - we should re-handshake.
                handshake_response = self.handshake_with_server(client_id)

                # Return response, if successful give message to try again.
                upload_response.success = handshake_response.success
                upload_response.data = handshake_response
                upload_response.message = "Server lost MTE state, client needed to handshake again, handshake successful, please try again."
                upload_response.result_code = handshake_response.result_code
                upload_response.access_token = handshake_response.access_token
                return upload_response

        run_reseed = False
        if use_mte:
            # Restore Decoder.
            decoder = MteMkeDec.fromdefault()
            status = decoder.restore_state_b64(decoder_state)
            if status != MteStatus.mte_status_success:
                upload_response.success = False
                upload_response.result_code = Constants().RC_MTE_STATE_RETRIEVAL
                upload_response.message = "Failed to restore MTE Decoder engine. Status: {0} / {1}".format(
                    decoder.get_status_name(status), decoder.get_status_description(status))
                return upload_response

            # Start the chunking session.
            status = decoder.start_decrypt()
            if status != MteStatus.mte_status_success:
                upload_response.success = False
                upload_response.result_code = Constants().RC_MTE_DECODE_EXCEPTION
                upload_response.message = "Failed to start decode chunk. Status: {0} / {1}".format(
                    decoder.get_status_name(status), decoder.get_status_description(status))
                return upload_response

            # Decode the data.
            decoded_chunk = decoder.decrypt_chunk(
                base64.b64decode(text_response['Data']))
            clear_bytes, final_status = decoder.finish_decrypt()
            if clear_bytes == NULL:
                clear_bytes = bytearray(1)
            if final_status != MteStatus.mte_status_success:
                upload_response.success = False
                upload_response.result_code = Constants().RC_MTE_DECODE_EXCEPTION
                upload_response.message = "Failed to finish decode chunk. Status: {0} / {1}".format(
                    decoder.get_status_name(final_status), decoder.get_status_description(final_status))
                return upload_response

            # Set decoded message.
            decoded_message = decoded_chunk + clear_bytes

            # Return the server response.
            upload_response.data.server_response = decoded_message

            # Check Re-seed Interval.
            current_seed = encoder.get_reseed_counter()

            if current_seed > (self.max_reseed_interval * self.reseed_percentage):
                # Handshake with server and create MTE.
                handshake_response = self.handshake_with_server(client_id)
                if not handshake_response.success:
                    upload_response.success = handshake_response.success
                    upload_response.message = handshake_response.message
                    upload_response.result_code = handshake_response.result_code
                    upload_response.access_token = handshake_response.access_token
                    return upload_response

                # Set access token and Encoder and Decoder states.
                upload_response.data.decoder_state = handshake_response.data.decoder_state
                upload_response.data.encoder_state = handshake_response.data.encoder_state
                upload_response.access_token = handshake_response.access_token
                run_seed = True
            else:
                # Save the Decoder state.
                upload_response.data.decoder_state = decoder.save_state_b64()
                    
        else:
            # Return the server response.
            upload_response.data.server_response = base64.b64decode(
                text_response['Data'])

        # Update the jwt/access_token
        if run_reseed == False:
            upload_response.access_token = text_response['access_token']

        upload_response.success = True
        return upload_response

    def login_to_server(self, client_id: str, encoder_state: str, decoder_state:str) -> ResponseModel:
        """
        Login to the server using MTE Core.
        """
        response = ResponseModel()
        response.data = LoginResponse()
        response.data.encoder_state = encoder_state
        response.data.decoder_state = decoder_state

        # Login first before uploading file.
        # Use regular MTE.
        login_route = "/api/login"
        login = LoginModel()
        login.password = "P@ssw0rd!"
        login.username = "email@eclypses.com"

        # Serialize login model and encode.
        serialize_login = json.dumps(login, default=vars)

        # Encode outgoing message with MTE.
        enc = MteEnc.fromdefault()
        encoder_status = enc.restore_state_b64(encoder_state)
        if encoder_status != MteStatus.mte_status_success:
            response.message = "Failed to restore MTE Encoder engine. Status: {0}: {1}".format(enc.get_status_name(encoder_status), enc.get_status_description(encoder_status))
            response.success = False
            response.exception_uid = str(uuid.uuid4())
            response.result_code = Constants().RC_MTE_STATE_RETRIEVAL
            return response

        encode_result, encoder_status = enc.encode_b64(serialize_login)
        if encoder_status != MteStatus.mte_status_success:
            response.message = "Failed to encode the login. Status: {0}: {1}".format(enc.get_status_name(encoder_status), enc.get_status_description(encoder_status))
            response.success = False
            response.exception_uid = str(uuid.uuid4())
            response.result_code = Constants().RC_MTE_ENCODE_EXCEPTION
            return response

        # Save updated Encoder state.
        response.data.encoder_state = enc.save_state_b64()

        # Perform Login.
        headers = {
            "Content-Type": "text/plain",
            "accept": "*/*",
            "Content-Length": str(len(encode_result)),
            Constants().CLIENT_ID_HEADER: client_id
        }
        login_url = os.path.join(Constants().REST_API_NAME + login_route)            
        login_response = requests.post(
            url=login_url, data=encode_result, headers=headers)

        # Deserialize the result from login.
        server_response = login_response.json()

        # If there is an error then end.
        if server_response['Success'] == False:
            response.message = server_response['Message']
            response.success = server_response['Success']
            response.exception_uid = server_response["ExceptionUid"]
            response.result_code = server_response['ResultCode']
            return response

        # Set jwt/access_token
        response.access_token = server_response['access_token']

        # Decode the response and resave Decoder state.
        dec = MteDec.fromdefault()
        decoder_status = dec.restore_state_b64(decoder_state)
        if decoder_status != MteStatus.mte_status_success:
            response.message = "Failed to restore MTE Decoder engine. Status: {0}: {1}".format(dec.get_status_name(decoder_status), dec.get_status_description(decoder_status))
            response.success = False
            response.exception_uid = str(uuid.uuid4())
            response.result_code = Constants().RC_MTE_STATE_RETRIEVAL
            return response

        decoded_result, decoder_status = dec.decode_str_b64(server_response['Data'])
        if decoder_status != MteStatus.mte_status_success:
            response.message = "Failed to decode message. Status: {0}: {1}".format(dec.get_status_name(decoder_status), dec.get_status_description(decoder_status))
            response.success = False
            response.exception_uid = str(uuid.uuid4())
            response.result_code = Constants().RC_MTE_DECODE_EXCEPTION
            return response

        print ("Login response: {0}".format(decoded_result))
        response.data.decoder_state = dec.save_state_b64()
        response.data.login_message = decoded_result

        return response

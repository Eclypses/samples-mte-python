#!/usr/bin/env python3

import base64
from ctypes.wintypes import ULONG
from logging import exception
from random import randrange
import sys
import uuid
import requests
import json
import threading
import time
from asyncio.windows_events import NULL
from cachetools import Cache
from Crypto import Random
from AesHelper import AesHelper
from ResponseModel import ResponseModel
from HandshakeModel import HandshakeModel
from EclypsesECDH import EclypsesECDH
from Constants import Constants
from AesHelper import AES
from MteEnc import MteEnc
from MteDec import MteDec
from MteStatus import MteStatus

# Set max number of trips made per client.
MAX_NUMBER_OF_TRIPS = 10

# Declare different possible content types.
JSON_CONTENT_TYPE = "application/json"
TEXT_CONTENT_TYPE = "text/plain"

# Set Rest API URL
# Use this url to run locally against MteDemo API.
REST_API_NAME = "http://localhost:52603"
# Use this url to run against Eclypses API.
#REST_API_NAME = "https://dev-echo.eclypses.com"

# Encryption IV to put in memory cache.
_enc_IV = Random.new().read(AES.block_size)

# Create Aes Helper.
_enc = AesHelper()

_mte_client_state = Cache(maxsize=100)

# Create array for all conversation_ids.
_clients = dict()

# Reseed percentage.
RESEED_PERCENTAGE = 0.90

# Max Seed Interval for Clients.
_max_seed_interval = 0

def main():
    
    # Create session IV.

    # Prompt user to ask how many clients to create.
    print ("How many clients? (Enter number between 1-50)")
    client_num = int(input())

    # If client_num is outside the range, then default to 1.
    if client_num < 1 or client_num > 50:
        client_num = 1    

    # Run handshake and state for each client.
    for i in range(1, client_num + 1):
        # Handshake client with server.
        handshake_successful = handshake_with_server(client_id = i, current_conversation="")
        if not handshake_successful:
            print ("Handshake unsuccessful")
            raise exception("Handshake unsuccessful")

    # Completed create MTE states for number of clients.
    print ("Created MTE state for {0}'s".format(client_num))

    while True:
        # Iterate through clients and send out messages async.
        threads = list()
        for entry in _clients:
            th = threading.Thread(target=contact_server, args=(_clients[entry], entry))
            threads.append(th)
            th.start()

        for index, thread in enumerate(threads):
            thread.join()

        # End program or run contact server again.
        print ("Completed sending messages to {0} clients.".format(client_num))
        print ("Would you like to send additional messages to clients? (y/n)")
        send_additonal = input()
        if send_additonal != NULL and send_additonal.lower().startswith("n"):
            break

    return 0

def handshake_with_server(client_id: int, current_conversation: str = NULL)  -> bool:
    """
    Handshakes with the server.
    """
    print ("Performing Handshake for Client {0}".format(client_id))

    # Create client_id for this client.
    handshake = HandshakeModel()

    # If current converation guid passed in, then upate identifier.
    if len(current_conversation) > 0:
        handshake.conversation_identifier = current_conversation
    else:
        handshake.conversation_identifier = str(uuid.uuid4())

    # Add client to dictionary list if this is a new conversation.
    if client_id not in _clients:
        _clients[client_id] = handshake.conversation_identifier

    # Create Eclypses DH containers for handshake.
    encoder_ecdh = EclypsesECDH()
    decoder_ecdh = EclypsesECDH()

    # Get the public key to send to the other side.
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
        "Content-Type": JSON_CONTENT_TYPE,
        "accept": "*/*",
        Constants().CLIENT_ID_HEADER: handshake.conversation_identifier
    }
    handshake_response = requests.post(
        url=url, data=json.dumps(payload), headers=headers)

    # Deserialize the result from handshake.
    response = handshake_response.json()

    # If handshake was not successful, then break.
    if response['Success'] == False:
        print ("Error making DH handshake for Client {0}: {1}".format(client_id, response['Message']))
        return False

    # Create shared secret.
    encoder_shared_secret_model = encoder_ecdh.create_shared_secret(
          bytes(response['Data']['ClientEncoderPublicKey'], 'utf-8'))
    decoder_shared_secret_model = decoder_ecdh.create_shared_secret(
          bytes(response['Data']['ClientDecoderPublicKey'], 'utf-8'))

    # Create and store MTE Encoder and Decoder for this Client.
    mte_response = create_mte_states(personal=response['Data']['ConversationIdentifier'], 
        encoder_entropy=encoder_shared_secret_model, decoder_entropy=decoder_shared_secret_model,
        nonce=int(response['Data']['Timestamp']))

    # Clear container to ensure key is different for each client.
    encoder_ecdh = NULL
    decoder_ecdh = NULL

    # If there was an error, break out of loop.
    if mte_response.success == False:
        print ("Error creating MTE states for Client {0}: {1}".format(client_id, response['Message']))
        return False
    
    return True

def create_mte_states(personal: str, encoder_entropy: str, decoder_entropy: str, nonce: ULONG) -> ResponseModel:
    """
    Creates the MTE states.
    """
    global _max_seed_interval
    response = ResponseModel()    

    # Create the MTE Encoder
    encoder = MteEnc.fromdefault()
    encoder.set_entropy(base64.b64decode(encoder_entropy))
    encoder.set_nonce(nonce)
    status = encoder.instantiate(personal)
    if status != MteStatus.mte_status_success:
        print ("Error creating Encoder: Status: {0} / {1}".format(encoder.get_status_name(status), encoder.get_status_description(status)))
        response.message = "Error creating Encoder: Status: {0} / {1}".format(encoder.get_status_name(status), encoder.get_status_description(status))
        response.result_code = Constants().RC_MTE_STATE_CREATION
        response.success = False
        return response

    # Get the Max Seed Interval if NOT set.
    # This should be the same for ALL MTEs.
    if _max_seed_interval <= 0:
        _max_seed_interval = encoder.get_drbgs_reseed_interval(encoder.get_drbg())

    # Save and encrypt state.
    encoder_state = encoder.save_state_b64()
    encrypted_enc_state = _enc.encrypt(encoder_state, personal, _enc_IV)
    _mte_client_state[Constants().ENCODER_PREFIX+personal] = encrypted_enc_state

    # Create the MTE Decoder
    decoder = MteDec.fromdefault()
    decoder.set_entropy(base64.b64decode(decoder_entropy))
    decoder.set_nonce(nonce)
    status = decoder.instantiate(personal)
    if status != MteStatus.mte_status_success:
        print ("Error creating Decoder: Status: {0} / {1}".format(decoder.get_status_name(status), decoder.get_status_description(status)))
        response.message = "Error creating Decoder: Status: {0} / {1}".format(decoder.get_status_name(status), decoder.get_status_description(status))
        response.result_code = Constants().RC_MTE_STATE_CREATION
        response.success = False
        return response

    # Save and encrypt state.
    decoder_state = decoder.save_state_b64()
    encrypted_dec_state = _enc.encrypt(decoder_state, personal, _enc_IV)
    _mte_client_state[Constants().DECODER_PREFIX+personal] = encrypted_dec_state

    response.success = True
    response.result_code = Constants().RC_SUCCESS
    response.message = Constants().STR_SUCCESS

    return response

def contact_server(current_conversation: str, client_num: int):
    """
    Contacts the server.
    """
    # Randomly select number of trips between 1 and max number of trips.
    number_trips = randrange(1, MAX_NUMBER_OF_TRIPS)

    # Send message selected number of trips.
    for t in range (0, number_trips):
        # Get the current client Encoder state.
        encoder_state = _mte_client_state.get(Constants().ENCODER_PREFIX + current_conversation)
        decrypted_enc_state = _enc.decrypt(encoder_state, current_conversation, _enc_IV)

        # Restore the Encoder and ensure it works.
        encoder = MteEnc.fromdefault()
        encoder_status = encoder.restore_state_b64(decrypted_enc_state)
        if encoder_status != MteStatus.mte_status_success:
            print("Error restoring the Encoder MTE state for Client {0}: {1}".format(client_num, encoder.get_status_description(encoder_status)))
            raise exception("Error restoring the Encoder MTE state for Client {0}: {1}".format(client_num, encoder.get_status_description(encoder_status)))

        # Get the current client Decoder state.
        decoder_state = _mte_client_state.get(Constants().DECODER_PREFIX + current_conversation)
        decrypted_dec_state = _enc.decrypt(decoder_state, current_conversation, _enc_IV)

        # Restore the Decoder and ensure it works.
        decoder = MteDec.fromdefault()
        decoder_status = decoder.restore_state_b64(decrypted_dec_state)
        if decoder_status != MteStatus.mte_status_success:
            print("Error restoring the Decoder MTE state for Client {0}: {1}".format(client_num, decoder.get_status_description(decoder_status)))
            raise exception("Error restoring the Decoder MTE state for Client {0}: {1}".format(client_num, decoder.get_status_description(decoder_status)))

        # Encode message to send.
        message = "Hello from client {0} for the {1} time.".format(client_num, t+1)
        encoded_payload, encode_status = encoder.encode_b64(message)
        if encoder_status != MteStatus.mte_status_success:
            print ("Error encoding the message for Client {0}: {1}".format(client_num, encoder.get_status_description(encode_status)))
            raise exception("Error encoding the message for Client {0}: {1}".format(client_num, encoder.get_status_description(encode_status)))
        print ("Sending message {0} to multi client server.\n".format(message))

        # Send encoded message to server, putting client_id in header.
        url = Constants().REST_API_NAME + "/api/multiclient"
        payload = encoded_payload
        headers = {
            "Content-Type": TEXT_CONTENT_TYPE,
            "accept": "*/*",
            "Content-Length": str(len(encoded_payload)),
            Constants().CLIENT_ID_HEADER: current_conversation
        }

        multi_client_response = requests.post(
            url=url, data=payload, headers=headers)

        # Deserialize response.
        server_response = multi_client_response.json()
        if server_response['Success'] == False:
            # Check if we need to re-handshake.
            if server_response['ResultCode'] == Constants().RC_MTE_STATE_NOT_FOUND:
                # The server does not thave this client's state - we should re-handshake.
                handshake_is_successful = handshake_with_server(client_num, current_conversation)
                if handshake_is_successful == False:
                    print ("Error from server for client {0}: {1}".format(client_num, server_response['Message']))                   
                    raise Exception("Error from server for client {0}: {1}".format(client_num, server_response['Message']))
                return

        # Check Re-Seed Interval.
        current_seed = encoder.get_reseed_counter()
        if current_seed > (_max_seed_interval * RESEED_PERCENTAGE):
            # If we have reached the reseed percentage, then re-handshake.            handshake_is_successful = handshake_with_server(client_num, current_conversation)
            if handshake_is_successful == False:
                print ("Error from server for client {0}: {1}".format(client_num, server_response['Message']))
            return              
            
        # If this was successful, save the new Encoder state.
        encoder_state = encoder.save_state_b64()
        encrypted_enc_state = _enc.encrypt(encoder_state, current_conversation, _enc_IV)
        _mte_client_state[Constants().ENCODER_PREFIX+current_conversation] = encrypted_enc_state

        # Decode the incoming message.
        decoded_message, decoder_status = decoder.decode_str_b64(server_response['Data'])
        if decoder.status_is_error(decoder_status):
            print ("Error decoding the message for Client {0}: {1}".format(client_num, decoder.get_status_description(decoder_status)))
            raise exception("Error decoding the message for Client {0}: {1}".format(client_num, decoder.get_status_description(decoder_status)))

        # If decode is successful, save the new Decoder state.
        decoder_state = decoder.save_state_b64()
        encrypted_dec_state = _enc.encrypt(decoder_state, current_conversation, _enc_IV)
        _mte_client_state[Constants().DECODER_PREFIX+current_conversation] = encrypted_dec_state

        print ("Received {0} from multi-client server.\n".format(decoded_message))

        # Sleep between each call a random amount of time.
        time.sleep(randrange(0,100)/1000)     

if __name__ == "__main__":
    sys.exit(main())

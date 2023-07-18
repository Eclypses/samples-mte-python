#!/usr/bin/env python3

from MteCiphers import MteCiphers
from MteHashes import MteHashes
from MteDrbgs import MteDrbgs
from MteVerifiers import MteVerifiers
from MteStatus import MteStatus
from MteBase import MteBase
from MteMkeEnc import MteMkeEnc
from MteMkeDec import MteMkeDec
import os, sys, requests, json
from pathlib import Path

# Application constants.
buffer_size = 1024
default_extension = ".txt"
nonce = 1
identifier = "mySecretIdentifier"
company_name = ""
company_license = ""

def main():
    # Prompt for file path.
    input_file = input("Please enter path to file:\n")
    file_path = Path(input_file)

    if not file_path.is_file():
        raise Exception("Path does not exist!\n")   

    # Get the file extension.
    extension = file_path.suffix

    # Set encoded and decoded file names.
    encoded_file_name = "encodedFile" + extension
    decoded_file_name = "decodedFile" + extension

    # Open the input file.
    in_file = open(file_path,'rb')

    # Check if the encoded file we will create is already there.
    # If present then delete it.
    try: 
        if Path(encoded_file_name).is_file():
            Path(encoded_file_name).unlink()
    except:
        raise Exception("Error trying to delete file {0}\n".format(encoded_file_name))

    # Create MKE Encoder and Decoder.
    encoder = MteMkeEnc.fromdefault()
    decoder = MteMkeDec.fromdefault()

    # Check version and output to screen.
    mte_version = MteBase.get_version()
    print("Using MTE Version {0}".format(mte_version))

    # Check the license. If the license code is not required,
    # such as when using trial mode, this can be skipped.
    if not MteBase.init_license(company_name, company_license):
        encoder_status = MteStatus.mte_status_license_error
        raise Exception("There was an error attempting to initialize the MTE License.")

    # Check how long entropy we need, set default.
    # Providing Entropy in this fashion is insecure. This is for demonstration
    # purposes only and should never be done in practice.
    entropy_bytes = MteBase.get_drbgs_entropy_min_bytes(encoder.get_drbg())
    entropy = bytes("0" * entropy_bytes, 'utf-8')

    # Initialize Encoder.
    encoder.set_entropy(entropy)
    encoder.set_nonce(nonce)
    status = encoder.instantiate(identifier)
    if status != MteStatus.mte_status_success:
        (status,message) = MteBase.get_status_name(status),\
            MteBase.get_status_description(status)        
        raise Exception("Encoder instantiate error {0}: {1}".format(
            status,message))


    # Since entropy is zero'd after using it for the Encoder, fill in again.
    # Providing Entropy in this fashion is insecure. This is for demonstration
    # purposes only and should never be done in practice.
    entropy = bytes("0" * entropy_bytes, 'utf-8')

    # Initialize Decoder.
    decoder.set_entropy(entropy)
    decoder.set_nonce(nonce)
    status = decoder.instantiate(identifier)
    if status != MteStatus.mte_status_success:
        (status,message) = MteBase.get_status_name(status),\
            MteBase.get_status_description(status)        
        raise Exception("Decoder instantiate error {0}: {1}".format(
            status,message))

    # Initialize chunking.
    status = encoder.start_encrypt()
    if status != MteStatus.mte_status_success:
        (status,message) = MteBase.get_status_name(status),\
            MteBase.get_status_description(status)        
        raise Exception("MTE Encoder start_encrypt error {0}: {1}".format(
            status,message))

    # Create destination encoded file.
    destination = open(encoded_file_name, "wb")

    # Iterate through file and write to new location.
    while True:
        # Create buffer for file parts.
        buf = in_file.read(buffer_size)
        if len(buf) == 0:
            # Reached the end of the file, break out of loop.
            break     

        # Encrypt the chunk.
        status = encoder.encrypt_chunk(buf)
        if status != MteStatus.mte_status_success:
            (status,message) = MteBase.get_status_name(status),\
                MteBase.get_status_description(status)        
            raise Exception("Encode error {0}: {1}".format(
                status,message))

        # Write the encoded bytes to destination.
        if len(buf) > 0:
            destination.write(buf)

    # End of the file reached.
    # Finish the chunking session.
    finish_encode, status = encoder.finish_encrypt()
    if status != MteStatus.mte_status_success:
        (status,message) = MteBase.get_status_name(status),\
            MteBase.get_status_description(status)        
        raise Exception("Encode finish error {0}: {1}".format(
            status,message))

    # If there are bytes to write, write them to file.
    if len(finish_encode) > 0:
        destination.write(finish_encode)

    destination.close()
    in_file.close()

    print ("Finished creating {0} file".format(encoded_file_name))

    # Now read and decode file into new destination.
    f_read = open(Path(encoded_file_name),'rb')

    # Check if the decoded file we will create is already there.
    # If present then delete it.
    try: 
        if Path(decoded_file_name).is_file():
            Path(decoded_file_name).unlink()
    except:
        raise Exception("Error trying to delete file {0}\n".format(decoded_file_name))

    # Initialize decrypt chunking session.
    status = decoder.start_decrypt()
    if status != MteStatus.mte_status_success:
        (status,message) = MteBase.get_status_name(status),\
            MteBase.get_status_description(status)        
        raise Exception("MTE Decoder start_decrypt error {0}: {1}".format(
            status,message))

    # Create final destination file.
    final_destination = open(decoded_file_name, "wb")

    # Iterate through encoded file and decode.
    while True:
        # Create buffer for file parts.
        buf = f_read.read(buffer_size)
        if len(buf) == 0:
            # Reached the end of the file, break out of loop.
            break     

        # Decrypt the chunk.
        decoded = decoder.decrypt_chunk(buf)

        # Write the decoded bytes to destination.
        if len(decoded) > 0:
            final_destination.write(decoded)

    # End of file reached. Finish the decryption.
    # Write any remaining bytes to the file.
    finish_decode, status = decoder.finish_decrypt()
    if status != MteStatus.mte_status_success:
        (status,message) = MteBase.get_status_name(status),\
            MteBase.get_status_description(status)        
        raise Exception("Decode finish error {0}: {1}".format(
            status,message))

    if len(finish_decode) > 0:
        final_destination.write(finish_decode)

    # Print out success message.
    print ("Finished creating {0} file.".format(decoded_file_name))

    # Close the files.
    final_destination.close()
    f_read.close()     
        
    return 0

if __name__ == "__main__":
    sys.exit(main())

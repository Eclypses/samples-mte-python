# MTE Multiple Clients Demo    

## Introduction
The MTE requires each endpoint to be paired individually. For an endpoint to manage multiple MTE endpoints each endpoint must be tracked and be identifiable. When there are multiple MTE clients an easy way to manage all the clients is to save and restore the MTE state of each endpoint. This sample shows how to save and restore the MTE state in order to manage multiple MTE clients.

The sample uses a console application that will prompt the user for the number of clients to create. Then it will do the following for each client.

- Handshake with server to pair MTE
- Create MTE Encoder
- Encrypt and save MTE Encoder state
- Create MTE Decoder
- Encrypt and save MTE Decoder state

Sends a random number of messages, performing the following steps:

- Decrypts MTE Encoder state
- Restores MTE Encoder for client
- Encodes outgoing message with MTE
- Encrypts and saves updated MTE Encoder state
- Decrypts MTE Decoder state
- Restores MTE Decoder for client
- Decodes incoming message using MTE
- Encrypts and saves updated MTE Decoder state

User is then prompted to either send additional messages or end.

## Getting Started
This sample must be run in concert with an API server. In these samples there is a C# API Server Sample you can run locally or Eclypses provides an API at https://dev-echo.eclypses.com. 

It does require the user to add their MTE libraries to the code for it to work correctly. 

 - The MTE library should be put in the MteConsoleMultipleClients directory

This sample currently works with MTE 3.0.x. To use a different version of the MTE please do the following:

  - Copy files from the "/src/py" directory in the MTE archive to the MteConsoleMultipleClients directory.
  - Copy the corresponding MTE libary into the MteConsoleMultipleClients directory.


<div style="page-break-after: always; break-after: page;"></div>

## Contact Eclypses

<p align="center" style="font-weight: bold; font-size: 22pt;">For more information, please contact:</p>
<p align="center" style="font-weight: bold; font-size: 22pt;"><a href="mailto:info@eclypses.com">info@eclypses.com</a></p>
<p align="center" style="font-weight: bold; font-size: 22pt;"><a href="https://www.eclypses.com">www.eclypses.com</a></p>
<p align="center" style="font-weight: bold; font-size: 22pt;">+1.719.323.6680</p>

<p style="font-size: 8pt; margin-bottom: 0; margin: 300px 24px 30px 24px; " >
<b>All trademarks of Eclypses Inc.</b> may not be used without Eclypses Inc.'s prior written consent. No license for any use thereof has been granted without express written consent. Any unauthorized use thereof may violate copyright laws, trademark laws, privacy and publicity laws and communications regulations and statutes. The names, images and likeness of the Eclypses logo, along with all representations thereof, are valuable intellectual property assets of Eclypses, Inc. Accordingly, no party or parties, without the prior written consent of Eclypses, Inc., (which may be withheld in Eclypses' sole discretion), use or permit the use of any of the Eclypses trademarked names or logos of Eclypses, Inc. for any purpose other than as part of the address for the Premises, or use or permit the use of, for any purpose whatsoever, any image or rendering of, or any design based on, the exterior appearance or profile of the Eclypses trademarks and or logo(s).
</p>
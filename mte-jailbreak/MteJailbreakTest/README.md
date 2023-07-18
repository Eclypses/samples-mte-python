# MTE Jailbreak Demo    

## Introduction
The Jailbreak/root Detection Add-On is used in conjunction with the core MTE technology or any add-ons to aid in detecting jailbroken/rooted devices. The actual detection of a problem occurs in the decode operation, it will be detected in an implied way by the Decoder returning a "token does not exist" error when attempting to decode. This is a result of the Decoder not being in sync with the Encoder due to different nonce mutation. This error is general in the sense that it can imply other problems, so it is assumed that your jailbreak/root detection system has already verified valid communication before doing the jailbreak/root detection to eliminate the other possible reasons for the error. For more information, please see the official MTE developer guides.

**IMPORTANT**
  >The check between the two devices must use the same jailbreak/root detection platform algorithm to detect if the Encoder device has been jail broken. If you have a server that can receive communication from different types of devices, the platform of the device (eg. ios or android) must be known by the server in order to detect if the connecting device has been jail broken or not.

## Getting Started
The code sample in this project first instantiates the Encoder and Decoder with the entropy, nonce seed, and personalization string without the jailbreak/root detection. A message is sent to verify correct decoding. If that is successful, the same process is repeated with the same inputs, but with jailbreak/root detection enabled and verify correct decoding again. If it now gives the "token does not exist" error, the jailbreak/root detection has identified a problem.

This sample is meant to be run locally and does not require an outside API. It does require the user to add their MTE libraries to the code for it to work correctly. 

 - The MTE library should be put in the MteJailbreakTest directory

This sample currently works with MTE 3.0.x. To use a different version of the MTE please do the following:

  - Copy files from the "/src/py" directory in the MTE archive to the MteJailbreakTest directory.
  - Copy the corresponding MTE libary into the MteJailbreakTest directory.



<div style="page-break-after: always; break-after: page;"></div>

## Contact Eclypses

<p align="center" style="font-weight: bold; font-size: 22pt;">For more information, please contact:</p>
<p align="center" style="font-weight: bold; font-size: 22pt;"><a href="mailto:info@eclypses.com">info@eclypses.com</a></p>
<p align="center" style="font-weight: bold; font-size: 22pt;"><a href="https://www.eclypses.com">www.eclypses.com</a></p>
<p align="center" style="font-weight: bold; font-size: 22pt;">+1.719.323.6680</p>

<p style="font-size: 8pt; margin-bottom: 0; margin: 300px 24px 30px 24px; " >
<b>All trademarks of Eclypses Inc.</b> may not be used without Eclypses Inc.'s prior written consent. No license for any use thereof has been granted without express written consent. Any unauthorized use thereof may violate copyright laws, trademark laws, privacy and publicity laws and communications regulations and statutes. The names, images and likeness of the Eclypses logo, along with all representations thereof, are valuable intellectual property assets of Eclypses, Inc. Accordingly, no party or parties, without the prior written consent of Eclypses, Inc., (which may be withheld in Eclypses' sole discretion), use or permit the use of any of the Eclypses trademarked names or logos of Eclypses, Inc. for any purpose other than as part of the address for the Premises, or use or permit the use of, for any purpose whatsoever, any image or rendering of, or any design based on, the exterior appearance or profile of the Eclypses trademarks and or logo(s).
</p>
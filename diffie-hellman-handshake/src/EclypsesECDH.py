#!/usr/bin/env python3

##############################################################
##        Eclypses ECDH Key Generation Library              ##
## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ##
##                  Version: 1.0.1                          ##
##                    MIT License                           ##
##                                                          ##
## This library is designed to handle generating public     ##
## keys through the Elliptic Curve Diffie Hellman           ##
## algorithm. A corresponding shared key is then generated  ##
## based off each partners public key. A SHA256 digest      ##
## is then performed on the key and returned for use as     ##
## entropy in the Eclypses MTE.                             ##
##                                                          ##
##############################################################
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
import base64,hashlib,sys


class EclypsesECDH:
  
  def __init__(self):
    """Instantiate a key pair generator using the "Elliptic Curve" algorithm SECP256R1,
    commonly known as NIST P-256

    Attributes:
      __private_key (EllipticCurvePrivateKey): This is the private key for use internally only
    """
    self.__private_key = ec.generate_private_key(
      curve=ec.SECP256R1(),
      backend=default_backend()
      )

  def get_device_public_key(self) -> bytearray:
    """Generate a public key from the instantiated private key
    Format for exporting the public key is done through X.509 (PEM), removing
    the headers and footers for cross compatibility

    Returns:
      bytearray: Device public key in PEM format as a bytearray
    """

    public_bytes = self.__private_key.public_key().public_bytes(
      encoding=serialization.Encoding.PEM, 
      format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    ## Strip headers and footers from key
    public_key = ''.join(public_bytes.split('\n')[1:-2])

    return bytearray(public_key,"UTF-8")

  def create_shared_secret(self, partner_public_key: bytes) -> bytearray:
    """Create a shared key from the partner's public key
    A sha256 digest of the shared key is then returned in a bytearray
    This digest is then used as entropy as sha256 always creates 32 bytes
    of data

    Args:
      partner_public_key (bytes): The partners public key in bytes
    
    Raises:
      TypeError: Partner key not in bytes

    Returns:
      bytearray: No Exception: sha256 digest of shared key is returned in bytearray
      
      NoneType: Exception: None is returned
    """

    ## PEM key headers/footers are added to load the partner's public key
    ## properly and generate a shared secret
    _pem_header = "-----BEGIN PUBLIC KEY-----\n"
    _pem_footer = "\n-----END PUBLIC KEY-----"

    try:
      if isinstance(partner_public_key, bytes):
        public_bytes = bytes('{0}{1}{2}'.format(
          _pem_header,
          partner_public_key.decode(),
          _pem_footer),"UTF-8")

        ## Load the partner key with serialization as a pem key
        partner_public_key = serialization.load_pem_public_key(
          data=public_bytes,
          backend=default_backend()
          )

        ## Generate the shared key from partner's key
        shared_key = self.__private_key.exchange(ec.ECDH(),partner_public_key)

        ## Create a SHA256 digest of the shared key to return
        shared_secret = base64.b64encode(hashlib.sha256(shared_key).digest()).decode()

        ## Return the shared secret base64 digest to be used as entropy
        return bytearray(shared_secret,"UTF-8")
      
      else:
        raise TypeError

    ## Handle invalid partner key parameter type
    except TypeError:
      print("Shared key generation failed. Partner's public key was not in byte format.", file=sys.stderr)
      return None
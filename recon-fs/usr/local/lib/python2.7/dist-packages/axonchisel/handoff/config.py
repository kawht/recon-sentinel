"""
Ax_Handoff Crypto Configuration.

Contains constants defining aspects of the cryptography used by the
current variant of this package.

This module is not intended for public use.

------------------------------------------------------------------------------
Author: Dan Kamins <dos at axonchisel dot net>
Copyright (c) 2011 Dan Kamins, AxonChisel.net
"""


# ----------------------------------------------------------------------------


import hashlib

try:
    from Crypto.Cipher import AES
except ImportError as e:
    print "\n*** Please ensure that PyCrypto is installed! ***\n"
    raise


# ----------------------------------------------------------------------------


#
# Configure Crypto
#


HMAC_SECRET_HASH = hashlib.sha512
HMAC_DIGEST      = hashlib.sha1
HMAC_DIGEST_BITS = 160              # (160 = SHA1 digest size)
HMAC_BLOCK_BITS  = 512              # (512=64*8 = SHA1 fixed block size)
HMAC_KEY_BITS    = HMAC_BLOCK_BITS

AES_BLOCK_BITS   = 128              # (128=16*8 = AES fixed block size)
AES_KEY_BITS     = 128              # (128=16*8 = AES-128)
AES_MODE         = AES.MODE_CBC
AES_PAD_CHAR     = '\0'
AES_IV_BITS      = AES_BLOCK_BITS   # (match block size for CBC mode)

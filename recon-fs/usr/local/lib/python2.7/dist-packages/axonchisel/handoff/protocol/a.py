"""
Ax_Handoff Protocol (A variant).

Contains class representations of protocol elements:
  - Header
  - Body
  - Footer
  - Envelope (wraps header, body, footer)

Each element is able to serialize/unserialize to/from encoded strings.

Clients wishing to descend below the higher-level "Ax_Handoff" wrapper in the
object module may wish to use the "Envelope" element here.

Variant A (default full):
  - Full original standard (default) Ax_Handoff protocol.
  - Includes encryption, compression, signing
  

------------------------------------------------------------------------------
Author: Dan Kamins <dos at axonchisel dot net>
Copyright (c) 2011 Dan Kamins, AxonChisel.net
"""


# ----------------------------------------------------------------------------


from os import urandom
import hashlib
import zlib

try:
    from Crypto.Cipher import AES
except ImportError as e:
    print "\n*** Please ensure that PyCrypto is installed! ***\n"
    raise

import axonchisel.handoff.config as config
import axonchisel.handoff.util as util
import axonchisel.handoff.error as error
import axonchisel.handoff.protocol as protocol


# ----------------------------------------------------------------------------


#
# Protocol Elements: Header, Body, Footer.
#

    
class Header(protocol.Header):
    """Header protocol element."""

    VARIANT       = "A"

    @classmethod
    def from_serialized(cls, encstr):
        """Construct and return new object by unserializing encoded string. Raise UnserializeError on errors."""
        o = Header()
        o.unserialize(encstr)
        return o


class Footer(protocol.Footer):
    """Footer protocol element."""

    @classmethod
    def from_serialized(cls, encstr):
        """Construct and return new object by unserializing encoded string. Raise UnserializeError on errors."""
        o = Footer()
        o.unserialize(encstr)
        return o
    

class Body(protocol.Body):
    """Body protocol element."""

    def __init__(self):
        self.iv = None                # 16 bytes crypto initialization vector
        self.data = ""                # data byte string

    @classmethod
    def from_serialized(cls, encstr, secret=""):
        """Construct and return new object by unserializing encoded string. Raise UnserializeError on errors."""
        o = Body()
        o.unserialize(encstr, secret=secret)
        return o

    def serialize(self, secret=""):
        """Serialize self into string and return. Raise SerializeError on errors."""
        if secret == "":
            raise error.SerializeError("No secret specific for body serialization")
        if type(self.data) is not str:
            raise error.SerializeError("Body can only serialize byte str, but got {0}".format(type(self.data)))
        
        if not self.iv:               # if have iv then use it, else generate one
            self._random_iv()
            
        zdata = zlib.compress(self.data, 9)
        zdata_padded = util.rpad_string_crypto(zdata, block_size=config.AES_BLOCK_BITS/8)

        try:
            aes = AES.new(self._aes_key(secret), config.AES_MODE, self.iv)
        except TypeError as e:
            raise error.SerializeError("Unable to compute body AES key: {0!r}".format(e))
        encrypted = aes.encrypt(zdata_padded)
        dstr = "{iv}{enc}".format(iv=self.iv, enc=encrypted)
        s = util.ub64encode(dstr)
        return s

    def unserialize(self, encstr, secret=""):
        """Unserialize encoded string into self. Raise UnserializeError on errors."""
        if not isinstance(encstr, basestring):
            raise TypeError("Body can only unserialize from strings, but {0} given".format(type(encstr)))
        if secret == "":
            raise error.UnserializeError("No secret specific for body unserialization")

        try:
            dstr = util.ub64decode(encstr)
        except TypeError as e:
            raise error.UnserializeError("Error decoding body: {0!r}".format(e))
            
        if len(dstr) < (config.AES_IV_BITS/8):
            raise error.UnserializeError("Decoded body too short for iv ({0})".format(len(dstr)))
        self.iv = dstr[0:config.AES_IV_BITS/8]
        encrypted = dstr[config.AES_IV_BITS/8:]
        try:
            aes = AES.new(self._aes_key(secret), config.AES_MODE, self.iv)
        except TypeError as e:
            raise error.UnserializeError("Unable to compute body AES key: {0!r}".format(e))

        try:
            decrypted_zdata = aes.decrypt(encrypted)
        except ValueError as e:
            raise error.UnserializeError("Body decryption error: {0!r}".format(e))
            
        if len(decrypted_zdata) < (config.AES_BLOCK_BITS/8):
            raise error.UnserializeError("Padded compressed body too short ({0})".format(len(decrypted_zdata)))

        try:
            unpadded_zdata = util.unrpad_string_crypto(decrypted_zdata, block_size=config.AES_BLOCK_BITS/8)
        except ValueError as e:
            raise error.UnserializeError("Decryption failed (body data padding invalid): {0!r}".format(e))
            
        try:
            self.data = zlib.decompress(unpadded_zdata)
        except zlib.error as e:
            raise error.UnserializeError("Decrypted compressed data invalid: {0!r}".format(e))

    def _aes_key(self, secret=""):
        """Generate and return AES key (bytes) based on secret."""
        secret = util.cast_str(secret, "Secret phrase")
        secret_hash_256 = hashlib.sha256(secret).digest()
        return secret_hash_256[0:(config.AES_KEY_BITS/8)]

    def _random_iv(self):
        """Generate random RNG-shielded initialization vector bytes."""
        self.iv = hashlib.sha256(urandom(config.AES_IV_BITS/8)).digest()[:config.AES_IV_BITS/8]


# ----------------------------------------------------------------------------


#
# Protocol Envelope -- wraps Header, Body, Footer.
#


class Envelope(protocol.Envelope):
    """Protocol envelope wrapping header, body, footer."""

    def __init__(self):
        self.header = Header()
        self.body = Body()
        self.footer = Footer()

    @classmethod
    def from_serialized(cls, encstr, secret=""):
        """Construct and return new object by unserializing encoded string. Raise UnserializeError on errors."""
        o = Envelope()
        o.unserialize(encstr, secret=secret)
        return o



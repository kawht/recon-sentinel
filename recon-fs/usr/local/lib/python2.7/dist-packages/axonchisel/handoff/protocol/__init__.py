"""
Ax_Handoff Protocol Generic Support.

Contains variant-agnostic superclass representations of protocol elements:
  - Header
  - Body
  - Footer
  - Envelope (wraps header, body, footer)

Each element is able to serialize/unserialize to/from encoded strings.

Clients wishing to descend below the higher-level "Ax_Handoff" wrapper in the
object module may wish to use the "Envelope" elements here.

------------------------------------------------------------------------------
Author: Dan Kamins <dos at axonchisel dot net>
Copyright (c) 2011 Dan Kamins, AxonChisel.net
"""


# ----------------------------------------------------------------------------


import math
import hashlib
import hmac

import axonchisel.handoff.config as config
import axonchisel.handoff.util as util
import axonchisel.handoff.error as error


# ----------------------------------------------------------------------------


def get_variant(encstr):
    """Given encoded object (string), return the variant identifier (char)."""
    
    MAGIC         = "XH"

    if not isinstance(encstr, basestring):
        raise TypeError("Unable to determine variant from non-string {0}".format(type(encstr)))
    if len(encstr) < 3:
        raise error.UnserializeError("Not enough data (length {0})".format(len(encstr)))
    if encstr[0:2] != MAGIC:
        raise error.UnserializeError("Header magic '{0}' is not '{1}'".format(encstr[0:2], MAGIC))
    variant = encstr[2:3]
    
    return variant


# ----------------------------------------------------------------------------


#
# Protocol Elements Superclass.
#


class ProtocolElement(object):
    """Abstract superclass for protocol elements."""
    pass


# ----------------------------------------------------------------------------


#
# Protocol Elements: Header, Body, Footer.
#

    
class Header(ProtocolElement):
    """Header protocol element (Abstract Superclass)."""

    MAGIC         = "XH"
    VARIANT       = "?"  # (specified by subclasses)
    HMAC_BITS     = config.HMAC_DIGEST_BITS                         # (160 bits for SHA1)
    LENGTH_HMAC   = int(math.ceil(HMAC_BITS/8*4/3.0))               # 27
    LENGTH        = len(MAGIC) + len(VARIANT) + LENGTH_HMAC         # 30=2+1+27
    
    def __init__(self):
        self.body_hmac = ""    # byte string

    @classmethod
    def from_serialized(cls, encstr):
        """Construct and return new object by unserializing encoded string. Raise UnserializeError on errors."""
        o = Header()
        o.unserialize(encstr)
        return o

    def serialize(self):
        """Serialize self into string and return. Raise SerializeError on errors."""
        if len(self.body_hmac) != self.HMAC_BITS/8:
            raise error.SerializeError("Header body_hmac size {0}B is not {1}B".format(len(self.body_hmac), self.HMAC_BITS/8))
        return "{magic}{variant}{hmac}".format(
            magic=self.MAGIC, 
            variant=self.VARIANT, 
            hmac=util.ub64encode(self.body_hmac))

    def unserialize(self, encstr):
        """Unserialize encoded string into self. Raise UnserializeError on errors."""
        if not isinstance(encstr, basestring):
            raise TypeError("Header can only unserialize from strings, but {0} given".format(type(encstr)))
        if len(encstr) != self.LENGTH:
            raise error.UnserializeError("Header length {0} is not {1}".format(len(encstr), self.LENGTH))
        if encstr[0:2] != self.MAGIC:
            raise error.UnserializeError("Header magic '{0}' is not '{1}'".format(encstr[0:2], self.MAGIC))
        if encstr[2:3] != self.VARIANT:
            raise error.UnserializeError("Header variant '{0}' is not '{1}'".format(encstr[2:3], self.VARIANT))

        try:
            self.body_hmac = util.ub64decode(encstr[3:])
        except TypeError as e:
            raise error.UnserializeError("Error decoding body_hmac: {0!r}".format(e))

    def compute_body_hmac(self, serialized_body, secret=""):
        """Compute and return the body hmac based on serialized Body ProtocolElement passed."""
        return hmac.new(self._hmac_key(secret), serialized_body, config.HMAC_DIGEST).digest()

    def _hmac_key(self, secret=""):
        """Generate and return HMAC key (bytes) based on secret."""
        secret = util.cast_str(secret, "Secret phrase")
        secret_hash_512 = config.HMAC_SECRET_HASH(secret).digest()   # make lots of bits
        return secret_hash_512[0:(config.HMAC_KEY_BITS/8)]  # use all 512 bits


class Body(ProtocolElement):
    """Body protocol element (Abstract Superclass)."""
    pass


class Footer(ProtocolElement):
    """Footer protocol element (Abstract Superclass)."""

    MAGIC         = "HX"
    LENGTH        = len(MAGIC)       # 2
    
    def __init__(self):
        pass

    @classmethod
    def from_serialized(cls, encstr):
        """Construct and return new object by unserializing encoded string. Raise UnserializeError on errors."""
        o = Footer()
        o.unserialize(encstr)
        return o

    def serialize(self):
        """Serialize self into string and return. Raise SerializeError on errors."""
        return "{magic}".format(magic=self.MAGIC)

    def unserialize(self, encstr):
        """Unserialize encoded string into self. Raise UnserializeError on errors."""
        if not isinstance(encstr, basestring):
            raise TypeError("Footer can only unserialize from strings, but {0} given".format(type(encstr)))
        if len(encstr) != self.LENGTH:
            raise error.UnserializeError("Footer length {0} is not {1}".format(len(encstr), self.LENGTH))
        if encstr[0:2] != self.MAGIC:
            raise error.UnserializeError("Footer magic '{0}' is not '{1}'".format(encstr[0:2], self.MAGIC))
    

# ----------------------------------------------------------------------------


#
# Protocol Envelope -- wraps Header, Body, Footer.
#


class Envelope(ProtocolElement):
    """Protocol envelope wrapping header, body, footer (Abstract Superclass)."""

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

    def serialize(self, secret=""):
        """Serialize self into string and return. Raise SerializeError on errors."""
        if secret == "":
            raise error.SerializeError("No secret specific for envelope serialization")

        # Serialize body and calc/store HMAC in header:
        s_body = self.body.serialize(secret=secret)
        try:
            self.header.body_hmac = self.header.compute_body_hmac(s_body, secret=secret)
        except TypeError as e:
            raise error.SerializeError("Unable to compute body HMAC: {0!r}".format(e))
        
        # Serialize remainder:
        s_header = self.header.serialize()
        s_footer = self.footer.serialize()
        
        # Combine and return:
        envelope = "{h}{b}{f}".format(h=s_header, b=s_body, f=s_footer)
        return envelope

    def unserialize(self, encstr, secret=""):
        """Unserialize encoded string into self. Raise UnserializeError on errors."""
        if not isinstance(encstr, basestring):
            raise TypeError("Envelope can only unserialize from strings, but {0} given".format(type(encstr)))
        if secret == "":
            raise error.UnserializeError("No secret specific for envelope unserialization")

        # Break envelope into chunks (fixed size header and footer, variable body):
        enc_header = encstr[:Header.LENGTH]
        enc_footer = encstr[-Footer.LENGTH:]
        enc_body = encstr[Header.LENGTH:-Footer.LENGTH]

        # Unserialize header and verify HMAC against computed body HMAC:
        self.header.unserialize(enc_header)
        try:
            body_hmac = self.header.compute_body_hmac(enc_body, secret=secret)
        except TypeError as e:
            raise error.UnserializeError("Unable to compute body HMAC: {0!r}".format(e))
        if self.header.body_hmac != body_hmac:
            raise error.DataTamperedError("Body HMAC ({0!r}) does not match header's ({1!r}).".format(body_hmac, self.header.body_hmac))

        # Unserialize and verify remainder:
        self.body.unserialize(enc_body, secret=secret)
        self.footer.unserialize(enc_footer)


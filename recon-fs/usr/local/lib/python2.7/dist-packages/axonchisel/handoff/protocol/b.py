"""
Ax_Handoff Protocol (B variant).

Contains class representations of protocol elements:
  - Header
  - Body
  - Footer
  - Envelope (wraps header, body, footer)

Each element is able to serialize/unserialize to/from encoded strings.

Clients wishing to descend below the higher-level "Ax_Handoff" wrapper in the
object module may wish to use the "Envelope" element here.

Variant B (minimal):
  - Simplified concise version of Ax_Handoff protocol.
  - Includes compression and signing, but not encryption.
  - Faster to encode/decode due to lack of AES.
  - Shorter encoded strings (by ~20-40 chars) due to lack of AES iv + padding.
  - Easier integration with platforms without good AES support.
  

------------------------------------------------------------------------------
Author: Dan Kamins <dos at axonchisel dot net>
Copyright (c) 2011 Dan Kamins, AxonChisel.net
"""


# ----------------------------------------------------------------------------


import zlib

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

    VARIANT       = "B"

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
        
        zdata = zlib.compress(self.data, 9)
        dstr = "{enc}".format(enc=zdata)
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
            
        zdata = dstr[0:]
        try:
            self.data = zlib.decompress(zdata)
        except zlib.error as e:
            raise error.UnserializeError("Decrypted compressed data invalid: {0!r}".format(e))



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



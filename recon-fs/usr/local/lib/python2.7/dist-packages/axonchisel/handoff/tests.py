"""
Ax_Handoff Unit Tests.

To run these tests from the command line:

    $ python -m axonchisel.handoff.tests

------------------------------------------------------------------------------
Author: Dan Kamins <dos at axonchisel dot net>
Copyright (c) 2011 Dan Kamins, AxonChisel.net
"""


# ----------------------------------------------------------------------------


import os
import hashlib
import cgi
import copy
import unittest

import axonchisel.handoff.util as util
import axonchisel.handoff.protocol as protocol
import axonchisel.handoff.protocol.a as protocol_a
import axonchisel.handoff.protocol.b as protocol_b
import axonchisel.handoff.error as error
from axonchisel.handoff.object import Ax_Handoff


# ----------------------------------------------------------------------------


# ----------------------------------------------------------------------------
# Unit Tests: Utility Functions
#


class Test_ub64(unittest.TestCase):
    """Test 'base64url' Base64 encoding and decoding utilities."""

    def setUp(self):
        pass

    def test_encode_decode(self):
        for slen in range(0, 500):
            s = os.urandom(slen)
            senc = util.ub64encode(s)
            senc_urlenc = cgi.escape(senc)  # test URL-safeness
            self.assertEqual(senc, senc_urlenc)
            sdec = util.ub64decode(senc)         # test enc/dec equivalent
            self.assertEqual(s, sdec)


class Test_rpad(unittest.TestCase):
    """Test padding and unpadding utilities."""

    def setUp(self):
        pass

    def test_rpad(self):
        for block_size in range(4, 64, 4):
            for slen in range(0, 128):
                s = "x" * slen
                spad = util.rpad_string(s, block_size=block_size, pad_char='p')
                self.assertEqual(len(spad) % block_size, 0)
                self.assertTrue(len(spad) >= len(s))

    def test_rpad_crypto(self):
        for block_size in range(4, 64, 4):
            for slen in range(0, 128):
                s = "x" * slen
                spad = util.rpad_string_crypto(s, block_size=block_size)
                self.assertEqual(len(spad) % block_size, 0)
                self.assertTrue(len(spad) > len(s))
                self.assertEqual(ord(spad[-1]), len(spad) - len(s))
                sunpad = util.unrpad_string_crypto(spad, block_size=block_size)
                self.assertEqual(sunpad, s)



# ----------------------------------------------------------------------------
# Unit Tests: Protocol
#


class Test_Header(unittest.TestCase):
    """Test Header protocol elements."""

    def setUp(self):
        self.body = "This is a test body content here."
        self.body_hmac = hashlib.sha1(self.body).digest()

    def test_serialize_unserialize_a(self):
        self._test_serialize_unserialize(protocol_a)

    def test_serialize_unserialize_b(self):
        self._test_serialize_unserialize(protocol_b)

    def _test_serialize_unserialize(self, protocol1):

        # Serialize and test length:
        h1 = protocol1.Header()
        h1.body_hmac = self.body_hmac
        hs1 = h1.serialize()
        self.assertEqual(len(hs1), protocol1.Header.LENGTH)

        # Unserialize and compare body:
        h2 = protocol1.Header.from_serialized(hs1)
        self.assertEqual(h2.body_hmac, h1.body_hmac)

        # Reserialize and compare with original serialization:
        hs2 = h2.serialize()
        self.assertEqual(hs2, hs1)

        # Test adding and replacing chars to trigger errors:
        for rep_char in ['%', '^', ')']:
            for pos in range(protocol1.Header.LENGTH + 1):
                hs2x = hs2[:pos] + rep_char + hs2[pos:]  # add char
                self.assertRaises(error.UnserializeError, protocol1.Header.from_serialized, hs2x)
            for pos in range(protocol1.Header.LENGTH):
                hs2x = hs2[:pos] + rep_char + hs2[pos+1:]  # replace char
                self.assertRaises(error.UnserializeError, protocol1.Header.from_serialized, hs2x)


class Test_Footer(unittest.TestCase):
    """Test Footer protocol elements."""

    def setUp(self):
        pass

    def test_serialize_unserialize_a(self):
        self._test_serialize_unserialize(protocol_a)

    def test_serialize_unserialize_b(self):
        self._test_serialize_unserialize(protocol_b)

    def _test_serialize_unserialize(self, protocol1):

        # Serialize and test length:
        f1 = protocol1.Footer()
        fs1 = f1.serialize()
        self.assertEqual(len(fs1), protocol1.Footer.LENGTH)

        # Unserialize:
        f2 = protocol1.Footer.from_serialized(fs1)

        # Reserialize and compare with original serialization:
        fs2 = f2.serialize()
        self.assertEqual(fs2, fs1)

        # Test adding and replacing chars to trigger errors:
        for rep_char in ['%', '^', ')']:
            for pos in range(protocol1.Footer.LENGTH + 1):
                fs2x = fs2[:pos] + rep_char + fs2[pos:]  # add char
                self.assertRaises(error.UnserializeError, protocol1.Footer.from_serialized, fs2x)
            for pos in range(protocol1.Footer.LENGTH):
                fs2x = fs2[:pos] + rep_char + fs2[pos+1:]  # replace char
                self.assertRaises(error.UnserializeError, protocol1.Footer.from_serialized, fs2x)


class Test_Body(unittest.TestCase):
    """Test Body protocol elements."""

    def setUp(self):
        self.secret = "This is my secret phrase here! It's long & strong."
        self.data = "ADVANCE CONCORD TO WESTERN RIDGE 0600. FIRE FLARE TO INITIATE ARTILLERY. CONCORD IS GO. CONCORD IS GO."

    def test_serialize_unserialize_a(self):
        self._test_serialize_unserialize(protocol_a)

    def test_serialize_unserialize_b(self):
        self._test_serialize_unserialize(protocol_b)

    def _test_serialize_unserialize(self, protocol1):

        # Serialize:
        b1 = protocol1.Body()
        b1.data = self.data
        bs1 = b1.serialize(secret=self.secret)

        # Unsserialize:
        b2 = protocol1.Body.from_serialized(bs1, secret=self.secret)
        self.assertEqual(b2.data, b1.data)

        # Test errors from tampering with encryption:
        if protocol == protocol_a:
            
            # Test adding and replacing chars in secret to trigger errors:
            for rep_char in ['%', '^', ')', 'a', '1']:
                for pos in range(len(self.secret) + 1):
                    secretx = self.secret[:pos] + rep_char + self.secret[pos:]  # add char
                    self.assertRaises(error.UnserializeError, protocol1.Body.from_serialized, bs1, secret=secretx)
            for pos in range(len(self.secret)):
                secretx = self.secret[:pos] + chr(ord(self.secret[pos]) ^ 0xff) + self.secret[pos+1:]  # bit flip char
                self.assertRaises(error.UnserializeError, protocol1.Body.from_serialized, bs1, secret=secretx)

            # Test adding and replacing chars to encrypted string to trigger errors:
            for rep_char in ['%', '^', ')', 'a', '1']:
                for pos in range(len(bs1) + 1):
                    bs1x = bs1[:pos] + rep_char + bs1[pos:]  # add char
                    self.assertRaises(error.UnserializeError, protocol1.Body.from_serialized, bs1x, secret=self.secret)
            for rep_char in ['%', '^', ')']:
                for pos in range(len(bs1)):
                    bs1x = bs1[:pos] + rep_char + bs1[pos+1:]  # replace char
                    self.assertRaises(error.UnserializeError, protocol1.Body.from_serialized, bs1x, secret=self.secret)

        # Test error from serialize non-string 2 (list):
        b2 = protocol1.Body()
        b2.data = [1, 2, 3]
        self.assertRaises(error.SerializeError, protocol1.Body.serialize, b2, secret=self.secret)

        # Test error from serialize non-string 2 (unicode):
        b3 = protocol1.Body()
        b3.data = u"This should be rejected as not a byte string."
        self.assertRaises(error.SerializeError, protocol1.Body.serialize, b3, secret=self.secret)


class Test_Envelope(unittest.TestCase):
    """Test full header+body+footer protocol envelopes."""

    def setUp(self):
        self.secret = "This is my secret phrase here! It's long & strong."
        self.data = "ADVANCE CONCORD TO WESTERN RIDGE 0600. FIRE FLARE TO INITIATE ARTILLERY. CONCORD IS GO. CONCORD IS GO."

    def test_serialize_unserialize(self):
        self._test_serialize_unserialize(protocol_a)

    def test_serialize_unserialize(self):
        self._test_serialize_unserialize(protocol_b)

    def _test_serialize_unserialize(self, protocol1):

        # Build envelope:
        e1 = protocol1.Envelope()
        e1.body.data = self.data
        
        # Serialize:
        es1 = e1.serialize(secret=self.secret)

        # Test variant detection:
        self.assertEqual(protocol.get_variant(es1), protocol1.Header.VARIANT)
        
        # Test URL-safeness:
        self.assertEqual(es1, cgi.escape(es1))
        
        # Unserialize:
        e2 = protocol1.Envelope.from_serialized(es1, secret=self.secret)
        self.assertEqual(e1.body.data, e2.body.data)
        
        # Reserialize:
        es2 = e2.serialize(secret=self.secret)
        self.assertEqual(es1, es2)
        
        # Alter header HMAC (overwrite a 0 prefix) and trigger HMAC verify error:
        es1x = es1[:3] + '000000000000' + es1[15:]
        self.assertRaises(error.UnserializeError, protocol1.Envelope.from_serialized, es1x, secret=self.secret)



# ----------------------------------------------------------------------------
# Unit Tests: High Level Object API
#

class Test_Object(unittest.TestCase):
    """Test high level object wrapper."""

    def setUp(self):
        self.secret = "This is my secret phrase here! It's long & strong."
        self.obj = {
            "msg": "ADVANCE CONCORD TO WESTERN RIDGE 0600. FIRE FLARE TO INITIATE ARTILLERY. CONCORD IS GO. CONCORD IS GO.",
            "coords": [1.4325, -88.095],
            "d": { "foo": "Mike", "bar": [10, 12] }
        }
            

    def test_serialize_unserialize_a(self):
        self._test_serialize_unserialize('A')

    def test_serialize_unserialize_b(self):
        self._test_serialize_unserialize('B')

    def _test_serialize_unserialize(self, variant):

        # Encode/decode and compare:
        es1 = Ax_Handoff.encode(self.obj, secret=self.secret, variant=variant)
        obj2 = Ax_Handoff.decode(es1, secret=self.secret)
        self.assertEqual(self.obj, obj2)

        # Test encoding non-JSON-congruent data:
        obj3x = copy.copy(self.obj)
        obj3x['obj'] = object()  # objects cannot be JSON-encoded
        self.assertRaises(error.SerializeError, Ax_Handoff.encode, obj3x, secret=self.secret)


class Test_Unicode(unittest.TestCase):
    """Test Unicode in secret phrase and data payload."""

    def setUp(self):
        self.secret = u"\xfe\xeb\xebp-\xfe\xf6p! \xf1\xebv\xebr f\xf6rg\xe9t!"
        self.obj = u"#2 p\xe9nc\xedl"

    def test_serialize_unserialize_a(self):
        self._test_serialize_unserialize('A')

    def test_serialize_unserialize_b(self):
        self._test_serialize_unserialize('B')

    def _test_serialize_unserialize(self, variant):

        # Encode/decode and compare:
        es1 = Ax_Handoff.encode(self.obj, secret=self.secret, variant=variant)
        obj2 = Ax_Handoff.decode(es1, secret=self.secret)
        self.assertEqual(self.obj, obj2)
        
        # Test unicode version of encoded string:
        es1u = unicode(es1)
        obj2u = Ax_Handoff.decode(es1u, secret=self.secret)


class Test_Types(unittest.TestCase):
    """Test error handling of bad types."""

    def setUp(self):
        self.secret = "This is my secret phrase here! It's long & strong."
        self.obj = [5]
        self.not_string = [1,2,3]

    def test_serialize_unserialize_a(self):
        self._test_serialize_unserialize('A')
        
    def test_serialize_unserialize_b(self):
        self._test_serialize_unserialize('B')

    def _test_serialize_unserialize(self, variant):

        # Test non-string secrets to verify error handling:
        self.assertRaises(error.SerializeError, Ax_Handoff.encode, self.obj, secret=12345, variant=variant)
        self.assertRaises(error.UnserializeError, Ax_Handoff.decode, "fakeencstr", secret=12345)

        # Test non-string encstr to verify error handling:
        self.assertRaises(TypeError, Ax_Handoff.decode, self.not_string, secret=self.secret)
        self.assertRaises(TypeError, protocol_a.Header.from_serialized, self.not_string, secret=self.secret)
        self.assertRaises(TypeError, protocol_a.Body.from_serialized, self.not_string, secret=self.secret)
        self.assertRaises(TypeError, protocol_a.Footer.from_serialized, self.not_string, secret=self.secret)
        self.assertRaises(TypeError, protocol_a.Envelope.from_serialized, self.not_string, secret=self.secret)


# ----------------------------------------------------------------------------


if __name__ == '__main__':
    unittest.main()


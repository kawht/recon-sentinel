**Ax_Handoff: Easy secure protocol for passing encrypted structured data over 
unencrypted channels (such as URLs) while maintaining tamper-proof integrity.**

//////////////////////////////////////////////////////////////////////////////

==============================================================================
Overview
==============================================================================

------------------------------------------------------------------------------
Official Links
------------------------------------------------------------------------------

Python Package Index:
    http://pypi.python.org/pypi/Ax_Handoff/

Source Repository & Issue Tracker:
    https://bitbucket.org/dkamins/ax_handoff/

Advanced Documentation (optional):
    https://bitbucket.org/dkamins/ax_handoff/src/default/docs/


------------------------------------------------------------------------------
About This Package
------------------------------------------------------------------------------

This package (``axonchisel.handoff`` a.k.a. ``Ax_Handoff``) provides a low
level protocol and a high level wrapper encapsulating a number of complex
features provided by other libraries and exposes a simple interface
that allows a developer to exchange or "hand off" secure chunks of
flexibly structured data (anything JSON-able) over untrusted 
communication channels between distributed components of a system.

The intricate details of thoroughly applied cryptography (AES encryption
and SHA-family hashes) (more `on crypto`_ below) and compression (gzip) are
hidden from the developer
integrating with this code such that the requirement of handing off chunks
of data in this manner becomes trivial and secure with little effort 
required and less than 5 lines of code (see `code samples`_ below!).

A primary motivation for this package is the case where a user
is redirected from one web app to another on a different domain
(i.e. where cookies cannot be shared) but important information
must be transmitted with guaranteed integrity and total opaqueness,
and other mechanisms (such as shared state or out-of-band data exchange)
are not possible or not desired.


------------------------------------------------------------------------------
Status
------------------------------------------------------------------------------

This library passes rigorous unit tests, is considered production-ready,
and has been used in live production systems for over a year.
As of this release, no security vulnerabilities or bugs have been identified.


------------------------------------------------------------------------------
Examples of Use
------------------------------------------------------------------------------

- A user linking to a supplemental 3rd party support or download 
  hosted web service site that offers content based on the user's
  subscription level, location, and other metadata.

- Exchanging session data (including logged in status) between two
  web apps managed by the same company but served by different platforms
  with no shared resources (often called "Single Sign On").

- Saving state in cookies that is not intended for users to
  see or modify in any way.

- Embedding complex data in links included in e-mails.


------------------------------------------------------------------------------
How it Works
------------------------------------------------------------------------------

One or more distributed components maintain a shared secret pass phrase.

Ax_Handoff converts a (JSON-congruent) Python object to JSON, 
compresses it, encrypts it, signs it, and packs it up into a custom 
envelope resulting in a guaranteed URL-safe string suitable for passing as 
query params.

Upon unpacking, integrity is verified, and the original JSON restored
as a Python object (or other object in non-Python environments).


------------------------------------------------------------------------------
Installation
------------------------------------------------------------------------------

The recommended way of installing this package is with "pip"::

    $ pip install pycrypto
    $ pip install Ax_Handoff

That's it.

If you don't have/want/like pip or that seems too easy for you,
then you should first download and install
PyCrypto from https://www.dlitz.net/software/pycrypto/.
Then download this (``Ax_Handoff``) package source and either copy/symlink the ``axonchisel`` 
directory from this package into your Python path or run::

    $ python setup.py install


//////////////////////////////////////////////////////////////////////////////


.. _code samples:

==============================================================================
Show me the code!
==============================================================================

-----------------------------------
Encoding / decoding complex objects
-----------------------------------

This brief example shows how easy it is to encode and decode complex objects::

    from axonchisel.handoff.object import Ax_Handoff

    secret = "mY s3cR3t p@$s phr@s3! Unb-b-b-re@k@ble!!"
    obj1 = {'foo': "Big Foo", 'bar': [10, 20.5, 30]}

    # Encode:
    enc = Ax_Handoff.encode(obj1, secret)
    # enc = 'XHADPtqHlzJuuFBpFnTmBz8Uk3tYTczT1oChKQyho9flBqlRbSTSgXBybJ59CI1N4_wnGl3nsuMwJ7ItMxixm8H9bCIsjv5M00At1rElGvuuJ7u4v4WAHX'

    # And decode back again:
    obj2 = Ax_Handoff.decode(enc, secret)
    # obj2 = {u'foo': u'Big Foo', u'bar': [10, 20.5, 30]}

-----------------------------------------------
Used with URLs for handing off between web apps
-----------------------------------------------

Use it in a URL::

    url = "http://my.app2.com/xfer/?data=" + Ax_Handoff.encode(user_data, shared_secret)
    redirect_to(url)

And on the receiving end::

    user_data = Ax_Handoff.decode(request.get('data'), shared_secret)



//////////////////////////////////////////////////////////////////////////////


==============================================================================
Details, Details
==============================================================================

------------------------------------------------------------------------------
Requirements
------------------------------------------------------------------------------

- Python 2.6 is required.

- PyCrypto (>=2.3) is required.  To install PyCrypto, try one of:

  - Run "pip install pycrypto" at the command prompt.
  - Download from https://www.dlitz.net/software/pycrypto/
    and follow installation instructions.


------------------------------------------------------------------------------
Protocol Variants
------------------------------------------------------------------------------

Ax_Handoff currently (as of 1.1.2) supports two protocol variants.
When using the recommended object level API, the variant may optionally
be specified at encoding time, and is automatically detected when decoding.

- Variant 'A' (default full): 

  - Full original standard (default) Ax_Handoff protocol.
  - Includes encryption, compression, signing.
  - Compatible with previous versions of Ax_Handoff.

- Variant 'B' (minimial):

  - Simplified concise version of Ax_Handoff protocol.
  - Includes compression and signing, but not encryption.
  - Faster to encode/decode due to lack of AES.
  - Shorter encoded strings (by ~20-40 chars) due to lack of AES iv + padding.
  - Easier integration with platforms without good AES support.



------------------------------------------------------------------------------
License
------------------------------------------------------------------------------

This open-source software is offered for free under standard MIT license
as contained in the LICENSE.txt file and described here:
See: http://www.opensource.org/licenses/mit-license.php



------------------------------------------------------------------------------
History
------------------------------------------------------------------------------

1.1.3 (2012-12-24)
------------------

- Refactor to support multiple protocol variants.
- Inclusion of new 'B' minimal (non-encrypting) variant.
- Miscellaneous cleanup.
- Status update to "production ready".


1.0.1 (2011-06-11)
------------------

- Fix over-aggressive type checking of encrypted text.
- Fix README dates.


1.0.0 (2011-06-11)
------------------

- Official v1 release.


0.9.4 (2011-06-10)
------------------

- Support for unicode secret phrases.
- Friendlier errors for invalid types.
- Crypto doc clarifications following positive security review.
- Major documentation update and formatting.
- Code cleanup.


0.8.4 (2011-06-08)
------------------

- First public preview release.




------------------------------------------------------------------------------
Bugs, Requests, Feedback, and Contributions
------------------------------------------------------------------------------

If you find any bugs or have feedback, please use our issue tracker:

    https://bitbucket.org/dkamins/ax_handoff/issues

You may also e-mail the author directly:

  Dan Kamins <dos at axonchisel dot net>

While you're free to fork this project, 
if you'd like to contribute, please send an e-mail first to one of the 
authors.
If you have patches, let us know and we'll roll them into the next release.
Our source repository is at:

    https://bitbucket.org/dkamins/ax_handoff/

Lastly, if you use this code for something interesting, drop us a line too!

------------------------------------------------------------------------------
Additional Documentation
------------------------------------------------------------------------------

Extensive clear documentation, cryptographic analysis, protocol 
specification, module overview, and more are available in the ``docs`` 
directory of this distribution.


//////////////////////////////////////////////////////////////////////////////


.. _on crypto:

==============================================================================
Cryptography Survey (or "Why should I trust this library?")
==============================================================================

------------------
How crypto is used
------------------

- Data encryption uses AES-128 (CBC mode) with random initialization vector.
  AES-128 is chosen over AES-256 due to recently discovered attacks
  (Biryukov and Khovratovich, 2009), making AES-128 preferable for now
  (Schneier, 2009).

- HMAC(SHA-1) is used for data integrity to sign the encrypted payload and
  prevent tampering, truncation, or errors in transit.

- Because HMAC is verified prior to decryption, the known CBC attack
  "Padding Oracle" (Vaudenay, Eurocrypt 2002) is not applicable.

- The AES initialization vector is random bytes (from os.urandom) which are 
  then further hashed to avoid potential RNG pattern analysis attacks on 
  potentially deficient random sources.

- Keys for AES-128 and HMAC(SHA-1) are generated by extracting bits from
  the SHA-256 and SHA-512 hashes of the secret phrase, respectively.

-----------
Other notes
-----------

- PBKDF2 is not used mainly to minimize external dependencies and keep
  code size and potential bugs down.  Due to HMAC signature of the encrypted
  stream and sufficient entropy of arbitrary pass phrases, this is not
  considered to be a vulnerability.

- As a further measure of precaution, clients are advised to avoid
  sharing details of possible decoding errors with end users who may 
  in the future find ways of using this information for new attacks.

- Details of the protocol specification sufficient to re-implement,
  interoperate with, or audit are provided in the ``docs/protocol.rst`` file.


//////////////////////////////////////////////////////////////////////////////

Copyright (c) 2012 Dan Kamins, AxonChisel.net



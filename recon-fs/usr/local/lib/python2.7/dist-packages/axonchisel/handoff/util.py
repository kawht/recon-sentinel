"""
Ax_Handoff Utility functions.

This module is not intended for public use.

------------------------------------------------------------------------------
Author: Dan Kamins <dos at axonchisel dot net>
Copyright (c) 2011 Dan Kamins, AxonChisel.net
"""


# ----------------------------------------------------------------------------


from base64 import b64encode, b64decode


# ----------------------------------------------------------------------------


#
# Internal Utility Functions
#


def cast_str(s, label):
    """
    Convert s (if needed) to regular (non-Unicode) string using UTF-8 encoding.
    Raise TypeError if of invalid format, using label param to describe the
    string (which is not included in the exception).
    """
    if type(s) is str:
        return s
    if type(s) is unicode:
        return s.encode('utf-8')
    raise TypeError("{0} must be valid unicode or str".format(label))
    
    
def rpad_string(s, block_size=16, pad_char='\0'):
    """Return right-padded version of string with length as multiple of block size."""
    mod = len(s) % block_size
    return s if not mod else (s + (block_size - mod) * pad_char)


def rpad_string_crypto(s, block_size=16):
    """
    Return special right-padded version of string with length as multiple of block size.
    Padding is ALWAYS applied even if already block size multiple.
    Padding is single byte repeated indicating number of padding bytes 
    (0x01 - 0x10 for block size 16).
    Based on recommendation from RFC 3852, PKCS #5, PKCS #7.
    """
    if block_size > 255:
        raise ValueError("Block size {0} too large (>255)".format(block_size))
    padcnt = block_size - len(s) % block_size
    pad_char = chr(padcnt)
    return s + pad_char * padcnt


def unrpad_string_crypto(s, block_size=16):
    """
    Undo rpad_string_crypto and return unpadded version of string.
    Removes trailing pad bytes as applied by rpad_string_crypto.
    """
    if len(s) < block_size:
        raise ValueError("Data ({0}) shorter than block size ({1})".format(len(s), block_size))
    padcnt = ord(s[-1])
    if padcnt > block_size:
        raise ValueError("Detected pad count ({0}) larger than block size ({1})".format(padcnt, block_size))
    if padcnt == 0:
        raise ValueError("Detected pad count ({0}) must be gt 0".format(padcnt))
    pad_char = chr(padcnt)
    for p in range(padcnt):
        if s[-p-1] != pad_char:
            raise ValueError("Padding contains invalid char '{0}' when expecting '{1}'".format(repr(s[-p]), repr(pad_char)))
    return s[:-p-1]


def pretty_bytes(bstr):
    """Return interpretation of byte string suitable for printing/logging."""
    return "[{len}] {repr}".format(len=len(bstr), repr=repr(bstr))


def ub64encode(bstr):
    """Return 'base64url' encoding (URL-safe) of byte string."""
    return b64encode(bstr).rstrip('=').replace('+','-').replace('/','_')


def ub64decode(estr):
    """Return decoded byte string from 'base64url' encoded (URL-safe) string."""
    estr = estr.replace('-','+').replace('_','/')
    estr = rpad_string(estr, 4, '=')
    return b64decode(estr)
    

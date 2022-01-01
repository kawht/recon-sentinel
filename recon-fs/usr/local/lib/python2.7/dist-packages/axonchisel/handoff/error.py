"""
Ax_Handoff Exceptions.

As a measure of precaution, clients are advised to avoid
sharing details of decoding errors with end users who may 
in the future find ways of using this information for new
attacks.

------------------------------------------------------------------------------
Author: Dan Kamins <dos at axonchisel dot net>
Copyright (c) 2011 Dan Kamins, AxonChisel.net
"""


# ----------------------------------------------------------------------------


# ----------------------------------------------------------------------------


#
# Exception Hierarchy
#


class Error(Exception):
    """Base Exception class."""
    def __str__(self):
        return unicode(self).encode('utf-8')


class SerializeError(Error):
    """Exception raised when serializing Ax_Handoff.

    Attributes:
        msg -- Error message
    """
    def __init__(self, msg):
        Error.__init__(self)
        self.msg = msg

    def __unicode__(self):
        return u"Ax_Handoff SerializeError: '{msg}'".format(msg=self.msg)


class UnserializeError(Error):
    """Exception raised when unserializing Ax_Handoff.

    Attributes:
        msg -- Error message
    """
    def __init__(self, msg):
        Error.__init__(self)
        self.msg = msg

    def __unicode__(self):
        return u"Ax_Handoff UnserializeError: '{msg}'".format(msg=self.msg)


class DataTamperedError(UnserializeError):
    """Exception raised when unserializing Ax_Handoff and data tampering detected.

    Attributes:
        msg -- Error message
    """
    def __init__(self, msg):
        UnserializeError.__init__(self, msg)

    def __unicode__(self):
        return u"Ax_Handoff DataTamperedError: '{msg}'".format(msg=self.msg)



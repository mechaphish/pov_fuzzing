#!/usr/bin/python

"""
Copyright (C) 2015 - Brian Caswell <bmc@lungetech.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""

# pylint: disable=too-few-public-methods


class NetworkFilterException(Exception):
    """
    An Exception class, used to signal that the session should be dropped
    """
    pass


class FilterData(object):
    """
    A string class intended to be used for passing around current offsets, and
    handling in-place content modification

    Attributes:
        data: underlying str data
        offset: current offset into 'data' that has been evaluated
    """
    def __init__(self, data):
        self.data = data
        self.offset = 0

    def __str__(self):
        return self.data[self.offset:]

    def __len__(self):
        return len(self.data)

    def __repr__(self):
        return '<FilterData: string:%s offset:%d>' % (repr(self.data),
                                                      self.offset)

    def seen(self):
        """
        Return the data that has been evaluated so far

        Arguments:
            None

        Returns:
            A str() instance that is the data prior to the current offset

        Raises:
            None
        """
        return self.data[:self.offset]

    def data_after(self, offset):
        """
        Return the data after a specified offset

        Arguments:
            offset

        Returns:
            A str() instance that is the data after the specified offset

        Raises:
            None
        """
        return self.data[offset:]

    def modify(self, offset, data):
        """
        Create a modified version of the FilterData instance, replacing content
        at a specified offset into the buffer.

        Arguments:
            offset: Offset into the current buffer to start the replacement
            data: Data that should be used as a replacement

        Returns:
            A FilterData instance that contains the modification

        Raises:
            AssertionError if the offset isn't an integer
            AssertionError if the data isn't a string
            AssertionError if the offset & data don't fit within the existing
                string
        """
        assert isinstance(offset, int)
        assert isinstance(data, str)
        assert offset + len(data) <= len(self.data)
        updated = FilterData(self.data[:offset] + data +
                             self.data[offset+len(data):])
        updated.offset = self.offset
        return updated


class FilterBaseClass(object):
    """
    Base class to ensure a few basic items are always implemented in Fitler*

    Attributes:
        CLIENT: used to signify the content is for data coming from the client
        SERVER: used to signify the content is for data coming from the server
    """
    CLIENT, SERVER = (0, 1)

    def __repr__(self):
        raise NotImplementedError(type(self))

    @staticmethod
    def _string_to_side(value):
        """
        Internal method that converts the session side to the enum values.

        Arguments:
            value: The string to be converted

        Returns:
            The enum value (CLIENT or SERVER) based on the string

        Raises:
            AssertionError if the value is not "client" or "server"
        """
        value = value.lower()
        assert value in ['client', 'server']

        if value.lower() == 'client':
            return FilterBaseClass.CLIENT
        else:
            return FilterBaseClass.SERVER

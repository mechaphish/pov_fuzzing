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

import re2 as re
import string
from . import base


class FilterSkip(base.FilterBaseClass):
    """
    Advance the offset into the current string buffer
    """
    def __init__(self, option):
        assert isinstance(option, list)
        assert len(option) == 1
        self.offset = int(option[0])

    def __repr__(self):
        return '[FilterSkip offset=%d]' % self.offset

    def cb_check(self, state, side, data):
        """
        Call back for evalating 'skip' rule options.

        Advance the 'offset', as long as the offset is within the buffer.
        """
        if data.offset + self.offset > len(data):
            return None
        data.offset += self.offset
        return data


class FilterBlock(base.FilterBaseClass):
    """
    Close the current session
    """
    def __repr__(self):
        return '[FilterBlock]'

    @staticmethod
    def cb_check(state, side, data):
        """
        Call back for the 'block' rule option.

        If the rule options all pass by the time this rule option is evaluated,
        drop the session.
        """
        raise base.NetworkFilterException('drop connection')


class FilterSide(base.FilterBaseClass):
    """
    Inspect content from only one side of the communication.
    """
    def __init__(self, option):
        assert isinstance(option, list)
        assert len(option) == 1
        side = option[0]
        self.side = self._string_to_side(side)

    def _get_side(self, side):
        """
        Translate the FilterBaseClass definition of CLIENT and SERVER to a
        string representation.
        """
        sides = {
            self.CLIENT: 'client',
            self.SERVER: 'server'
        }
        return sides[side]

    def __repr__(self):
        return '[FilterSide %s]' % (self._get_side(self.side))

    def cb_check(self, state, side, data):
        """
        Call back for the 'side' rule option.

        If the rule option side matches the side of the curernt data,
        continue processing.  Otherwise the rule stops processing.
        """
        if side == self.side:
            return data
        return None


class FilterState(base.FilterBaseClass):
    """
    Per-session named bitmask
    """
    def __init__(self, option):

        assert isinstance(option, list)
        assert len(option) == 2

        keyword, name = option

        allowed_keywords = ['set', 'unset', 'is', 'not']
        assert keyword in allowed_keywords
        self.keyword = keyword

        assert isinstance(name, str)
        assert len(name) > 0
        self.name = name

    def __repr__(self):
        return '[FilterState %s:%s]' % (self.keyword, self.name)

    def cb_check(self, state, side, data):
        """
        Call back for the 'state' rule option.

        If the rule option side matches the side of the curernt data,
        continue processing.  Otherwise the rule stops processing.
        """
        if self.keyword == 'set':
            state[self.name] = True
            return data
        elif self.keyword == 'unset':
            state[self.name] = False
            return data
        elif self.keyword == 'is':
            if self.name in state and state[self.name]:
                return data
        elif self.keyword == 'not':
            if self.name not in state or not state[self.name]:
                return data
        return None


class FilterMatch(base.FilterBaseClass):
    """
    Perform a string match on the input buffer
    """
    def __init__(self, option):
        assert isinstance(option, list)
        assert len(option) > 0

        self.depth = None
        self.replace = None

        value = option.pop(0)
        self.string = self._parse_str(value)

        for value in option:
            assert value[0] in ['depth', 'replace']
            assert isinstance(value[1], list)
            assert len(value[1]) == 1

            if value[0] == 'depth':
                assert self.depth is None, 'depth already defined'
                self.depth = int(value[1][0])
                assert self.depth >= len(self.string), 'depth (%d) has enough space for the string: %d' % (self.depth, len(self.string))

            if value[0] == 'replace':
                assert self.replace is None, 'replace already defined'
                self.replace = self._parse_str(value[1][0])
                assert len(self.replace) == len(self.string)

    @staticmethod
    def _parse_str(value):
        """
        Parse a quoted string that should include have C style hex escapped
        characters or alphanumeric and space characters.
        """
        assert value[0] == '"' and value[-1] == '"'
        value = value[1:-1]

        out = []
        while len(value):
            if value[0] in string.letters + string.digits + ' ':
                out.append(value[0])
                value = value[1:]
                continue

            assert value[0] == '\\', 'invalid string: %s' % value
            assert len(value) >= 2, 'invalid quoted string: %s' % value
            if value[1] == '"':
                out.append('"')
                value = value[2:]
                continue

            assert len(value) >= 3, 'invalid hex string: %s' % value
            assert value[1] == 'x', 'invalid hex mark: %s' % value
            assert value[2] in string.hexdigits
            assert value[3] in string.hexdigits
            out.append(chr(int(value[2:4], 16)))
            value = value[4:]

        return ''.join(out)

    def __repr__(self):
        return '[FilterMatch: string:%s depth:%s]' % (repr(self.string),
                                                      repr(self.depth))

    def cb_check(self, state, side, data):
        """
        Call back for the 'match' rule option.

        Validate the content of the rule option is in the remaining content
        buffer, replacing the value if a following 'replace' rule option
        exists.
        """
        raw_data = str(data)

        if self.depth is not None:
            raw_data = raw_data[:self.depth]

        # print "CHECKING", repr(raw_data), repr(self.string)
        try:
            offset = raw_data.index(self.string)
        except ValueError:
            return None

        data.offset += offset

        if self.replace is not None:
            data = data.modify(data.offset, self.replace)

        data.offset += len(self.string)

        return data


class FilterRegex(base.FilterBaseClass):
    """
    Perform a regular expression match on the input buffer
    """
    def __init__(self, option):
        assert isinstance(option, list)
        assert len(option) == 1

        value = option[0]
        assert value[0] == '"' and value[-1] == '"'

        self.regex_string = value[1:-1]
        assert '"' not in self.regex_string, "embeded quotes not handled"
        self.regex = re.compile(self.regex_string)

    def __repr__(self):
        return '<FilterRegex: re:%s>' % (repr(self.regex_string))

    def cb_check(self, state, side, data):
        """
        Call back for the 'regex' rule option.

        Validate the regex of the rule option against the remaining
        content buffer.
        """
        match = self.regex.match(str(data))
        if match:
            data.offset += match.end()
            return data
        return None

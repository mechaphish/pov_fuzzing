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

import sys
import re2 as re
import string
import logging
import copy
from . import ids_parser
from . import base
from . import rule_options


class Filter(base.FilterBaseClass):
    """ Filter - Rule evaluator for NetworkFilter

    An instance takes a parsed rule (from ids_parser), and on evaluation,
    iterates through the rule options, executing the appropriate rule option
    validation callback function.


    Attributes:
        name: name of the rule
        rule_type: Type of rule (should be admit, alert, or block)
        options: A list of rule options
        flush: The side of the session that should be flushed, if any
    """
    def __init__(self, data):
        self.name = None
        self.options = []
        self.rule_type = None
        self.flush = None
        self.load(data)

    def __repr__(self):
        rules = ' '.join([repr(x) for x in self.options])
        return '<Filter name=%s %s>' % (repr(self.name), rules)

    def load(self, data):
        """
        Load a rule (from ids_parser)

        Arguments:
            data: An ids_parser instance

        Returns:
            None

        Raises:
            AssertionError for various places validating the ids_parser struct
                is formed as expected
        """
        methods = {
            'match': rule_options.FilterMatch,
            'skip': rule_options.FilterSkip,
            'state': rule_options.FilterState,
            'side': rule_options.FilterSide,
            'regex': rule_options.FilterRegex,
        }

        assert isinstance(data, list)
        assert len(data) >= 2
        for option in data:
            assert isinstance(option, tuple)
            assert len(option) == 2

        keyword, rule_type = data.pop(0)
        assert keyword == 'rule_type'
        assert rule_type in ['admit', 'alert', 'block']
        self.rule_type = rule_type

        keyword, name = data.pop(0)
        assert keyword == 'name'
        assert isinstance(name, list)
        assert len(name) == 1
        name = name[0]
        assert name[0] == '"' and name[-1] == '"'
        self.name = name[1:-1]

        assert len(data) > 0
        if data[-1][0] == 'flush':
            keyword, value = data.pop()
            assert isinstance(value, list)
            assert len(value) == 1
            self.flush = self._string_to_side(value[0])


        for option in data:
            assert option[0] == 'option'
            assert isinstance(option[1], tuple)
            option = option[1]

            assert isinstance(option, tuple)
            assert option[0] in methods, 'unknown option %s' % repr(option[0])
            self.options.append(methods[option[0]](option[1]))

        if self.rule_type == 'block':
            self.options.append(rule_options.FilterBlock())

    def evaluate(self, state, side, data):
        """
        Evaluate a rule

        Arguments:
            state: A dict representing per-session states saved by 'state' rule
                options
            side: The side of the session the data is from.  needed by 'side'
                rule options
            data: FilterData instance representing data being analyzed

        Returns:
            None on rule match failure
            The evaluated 'data' on rule match success (could be modified by
                the rules, both offset and content)

        Raises:
            None
        """
        for option in self.options:
            logging.debug('testing %s : %s : %s', repr(state), repr(side),
                          repr(option))
            data = option.cb_check(state, side, data)
            logging.debug('result: %s', repr(data))
            if data is None:
                return None

        return data


class NetworkFilter(base.FilterBaseClass):
    """ NetworkFilter - A simplified network filter

    This class implements a parser for a simplified network parser, as defined
    above.

    Usage:
        f = NetworkFilter()
        f.parse(open('rules.txt', 'r').read())
        try:
            offset = f.evaluate(data)
        except NetworkFilterBlock as err:
            print "disconnect!"

    Attributes:
        filters: List of Filters
        offset:  Offset into the buffer for the current rule
        state:   Dict of states
    """

    def __init__(self, rules, buffer_size=None):
        self.filters = []
        self.state = {}
        self.sessions = {}
        parser = ids_parser.ids_parser()
        self.buffer_size = buffer_size
        self.debug = False

        lines = None
        if isinstance(rules, file):
            lines = rules.readlines()
        else:
            lines = rules.split('\n')

        for line in lines:
            logging.debug('parsing %s', repr(line))
            try:
                rule = parser.parse(line)
            except SyntaxError as error:
                logging.error('error parsing rule %s : %s', error,
                              repr(line))
                continue

            if len(rule):
                self.filters.append(Filter(rule))
        logging.debug('loaded %s', repr(self.filters))

    def __delitem__(self, session):
        if session in self.sessions:
            del self.sessions[session]

    def __repr__(self):
        return '<NetworkFilter %s>' % (repr(self.sessions))

    def __call__(self, session, side, data):
        """
        Evaluate a set of filters

        Arguments:
            side: side of the traffic being analyized.
            data: input string being analyzed

        Returns:
            data:  Returns the data that should be sent on.  (May be modified
                from 'data' on input, depending on rules that fired)

        Raises:
            AssertionError if side is invalid
            AssertionError data is not a string
            NetworkFilterBlock if the traffic should be blocked
        """
        assert side in (self.CLIENT, self.SERVER)
        assert isinstance(data, str)

        if session not in self.sessions:
            self.sessions[session] = {self.CLIENT: '', self.SERVER: '',
                                      'state': {}}

        offset = 0
       
        if self.buffer_size is not None:
            data_len = len(data)
            buff_len = len(self.sessions[session][side])
            if data_len + buff_len > self.buffer_size:
                logging.info("truncating inspection buffer by %d bytes" % data_len)
                self.sessions[session][side] = self.sessions[session][side][data_len:]

        combined = base.FilterData(self.sessions[session][side] + data)

        matched = []
        recent_matched = []

        should_flush = []
        # Iterate through all of the rules, until we've iterated and not seen a
        # match.
        while True:
            current_offset = combined.offset
            for _filter in self.filters:
                state = copy.copy(self.sessions[session]['state'])

                offset = combined.offset
                try:
                    ret = _filter.evaluate(state, side, combined)
                except base.NetworkFilterException:
                    raise base.NetworkFilterException('filter matched %s: %s' %
                                                      (repr(_filter.name),
                                                       repr(combined.seen())))
                if ret is None:
                    logging.debug('filter did not match %s: %s',
                                  repr(_filter.name), repr(str(combined)))
                    combined.offset = offset
                    continue

                # 'admit' rules parse traffic, but don't generate logs
                if _filter.rule_type != 'admit':
                    recent_matched.append(_filter.name)
                combined = ret
                if _filter.flush is not None:
                    should_flush.append(_filter.flush)
                    combined.offset += len(str(combined))
                
                self.sessions[session]['state'] = state

                # a rule matched.  continued analysis should happen from the beginning of the list
                break

            if len(recent_matched):
                matched += recent_matched
                recent_matched = []
            else:
                break

            # if we didn't match more content, stop processing
            if current_offset == combined.offset:
                break

        orig_len = len(self.sessions[session][side])
        self.sessions[session][side] = str(combined)

        for flush in should_flush:
            self.sessions[session][flush] = ''

        if self.debug:
            for side in self.sessions[session]:
                logging.debug('buffer %s : %s' % (repr(side), repr(self.sessions[session][side])))

        return combined.data_after(orig_len), matched


def main():
    """
    Sample usage of the NetworkFilter
    """
    logging.basicConfig(format='%(asctime)s - %(levelname)s : %(message)s',
                        level=logging.INFO, stream=sys.stdout)

    with open('examples/ids.rules', 'r') as rules:
        test_nf = NetworkFilter(rules)
    test_nf(0, test_nf.CLIENT, 'bob')
    test_nf(0, test_nf.CLIENT, 'b')
    test_nf(0, test_nf.SERVER, 'mom')
    test_nf(1, test_nf.SERVER, 'WUT')
    test_nf(0, test_nf.CLIENT, 'ob')
    del test_nf[0]
    print repr(test_nf)

if __name__ == '__main__':
    main()

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

import re2 as re
import sys


class Parser(object):
    """
    A custom pyPEG style recursive parser [0].

    Attributes:
        method: Base method for the parser
        comments: Regular Expression to identify comments

    0 - http://fdik.org/pyPEG/
    """
    AT_LEAST_ONE, MANY, OPTIONAL = range(-2, 1)

    def __init__(self, method, comments):
        assert callable(method)
        self.method = method

        if comments is not None:
            assert hasattr(comments, 'match')
        self.comments = comments

    def skip(self, text):
        """
        Skip whitespace and comments in the provided text

        Arguments:
            text: text to cleanup

        Returns:
            str without comments or whitespace

        Raises:
            None
        """
        text = text.strip()

        if self.comments is not None:
            while True and len(text):
                res = self.comments.match(text)
                if res:
                    text = text[len(res.group(0)):]
                else:
                    break
                text = text.strip()

        return text

    @staticmethod
    def parse_string(text, pattern):
        """
        Parse a 'str' element in the grammar, attempting to extract the
        specified string from the begining of the input.

        Arguments:
            text: current parsing buffer
            pattern: string that is being evaluated

        Returns:
            String containing the rest of the buffer, and the buffer that was
                removed from the begining of the buffer.

        Raises:
            SyntaxError if the pattern is not found within the buffer
        """
        if text.startswith(pattern):
            return text[len(pattern):], pattern
        else:
            actual = repr(text[:len(pattern)])
            raise SyntaxError('expecting %s, found %s' % (repr(pattern),
                                                          actual))

    @staticmethod
    def parse_regex(text, pattern):
        """
        Parse a RE element in the grammar, removing the matched data from the
        beginning of the input.

        Arguments:
            text: current parsing buffer
            pattern: re that is being evaluated

        Returns:
            String containing the rest of the buffer, and the buffer that was
                removed from the begining of the buffer.

        Raises:
            SyntaxError if the pattern is not found within the buffer
        """
        match = pattern.match(text)
        if match:
            text = text[len(match.group(0)):]
        else:
            raise SyntaxError('unhandled regular expression')
        return text, match.group(0)

    def parse_callable(self, text, pattern):
        """
        Call the specified method which should handle parsing of content,
        adding a tuple that specifies the name of the method and results from
        parsing with the method.

        Arguments:
            text: current parsing buffer
            pattern: method that is will be callled

        Returns:
            String containing the rest of the buffer, and a tuple that
                specifies the method name and result from the underlying
                function

        Raises:
            None
        """
        text, result = self.parse_item(text, pattern())
        return text, (pattern.__name__, result)

    def parse_list(self, text, pattern):
        """
        Try to parse each of the methods in the 'pattern' list, returning the
        results on the fist method that matches successfully.

        Arguments:
            text: current parsing buffer
            pattern: list of methods that should be tried

        Returns:
            The result of the underlying parsing method

        Raises:
            SyntaxError on none of the parsing methods in 'pattern' matching
                the input.
        """
        for sub_pattern in pattern:
            try:
                return self.parse_item(text, sub_pattern)
            except SyntaxError:
                pass
        raise SyntaxError('List failed: At least one item needs to match')

    def parse_tuple(self, text, pattern):
        """
        Iteratively parse the items in the 'pattern' tuple, adding the results
        from each method.  If the current item is an integer, use that to
        determine how many times that option should be parsed.  (A specified
        count, zero or one times, or many times)

        Arguments:
            text: current parsing buffer
            pattern: tuple of items that should be evaluated.  (methods, or
                counts of the following methods)

        Returns:
            The result of the underlying parsing methods

        Raises:
            SyntaxError if not enough data is provided to continue parsing as
                expected
        """
        results = []
        count = 1
        for sub_pattern in pattern:
            if not len(text):
                raise SyntaxError('more content needed')
            if isinstance(sub_pattern, int):
                count = sub_pattern
            else:
                if count in [self.MANY, self.OPTIONAL, self.AT_LEAST_ONE]:
                    seen = 0
                    while True:
                        if not len(text):
                            break
                        try:
                            text, result = self.parse_item(text, sub_pattern)
                        except SyntaxError:
                            break

                        if not isinstance(sub_pattern, str):
                            results.append(result)

                        if count == self.OPTIONAL:
                            break
                        seen += 1
                    if count == self.AT_LEAST_ONE and seen == 0:
                        raise SyntaxError('should see at least one option')
                else:
                    for _ in range(count):
                        text, result = self.parse_item(text, sub_pattern)
                        if not isinstance(sub_pattern, str):
                            results.append(result)
                count = 1

        return text, results

    def parse_item(self, text, item):
        """
        Based on the type of the provided parsing element (item), call the
        appropriate parse_* method with the provided input (text).

        Arguments:
            text: current parsing buffer
            item: data type of the current parse element

        Returns:
            The result of the underlying parsing method

        Raises:
            SyntaxError if the parse element is not a known type
        """
        # start by skipping comments/etc
        text = self.skip(text)
        if not len(text):
            return '', []

        method = None
        if isinstance(item, tuple):
            method = self.parse_tuple
        elif isinstance(item, list):
            method = self.parse_list
        elif isinstance(item, str):
            method = self.parse_string
        elif hasattr(item, 'match'):
            method = self.parse_regex
        elif callable(item):
            method = self.parse_callable
        else:
            raise SyntaxError("don't know how to parse %s" % type(item))

        return method(text, item)

    def parse(self, text):
        """
        Call the parse_item dispatcher to start recursing, from the provided
        input, validating that all of the data is ingested upon parsing.

        Arguments:
            text: current parsing buffer

        Returns:
            The result of the underlying parsing methods

        Raises:
            SyntaxError if the parsing methods do not ingest all of underlying
                data
        """
        text, result = self.parse_item(text, self.method())
        text = self.skip(text)
        if len(text):
            raise SyntaxError('unparsed text: %s' % repr(text))
        return result

COMMENT = re.compile(r'\s*#.*')
NUMBER = re.compile(r'\d+')
QUOTED_STRING = re.compile(r'"(?:[^"\\]|\\.)+"')
STRING = re.compile(r'"(?:\\x[a-fA-F0-9]|[a-zA-Z0-9 ])+"')
WORDCHAR = re.compile(r'\w+')


def ids_parser():
    """
    Create the underlying IDS parser

    Arguments:
        None

    Returns:
        A NetworkFilter rule parser

    Raises:
        None
    """
    def name():
        """
            name:"foo";
        """
        return 'name', ':', QUOTED_STRING, ';'


    def flush():
        """
            flush:server;
            flush:client;
        """
        return 'flush', ':', ['client', 'server'], ';'

    def replace():
        """ used by match()
            replace:"foo";
        """
        return 'replace', ':', QUOTED_STRING, ';'

    def depth():
        """ used by match()
            , 3
        """
        return ',', NUMBER

    def match():
        """
            match:"foo";
            match:"foo", 3;
            match:"foo"; replace:"bar";
            match:"foo", 3; replace:"bar";
        """
        return ('match', ':', STRING, Parser.OPTIONAL, depth, ';',
                Parser.OPTIONAL, replace)

    def state():
        """
            state:set, foo;
            state:unset, foo;
            state:is, foo;
            state:not, foo;
        """
        return 'state', ':', ['set', 'unset', 'is', 'not'], ',', WORDCHAR, ';'

    def side():
        """
            side: client;
            side: server;
        """
        return 'side', ':', ['client', 'server'], ';'

    def skip():
        """
            skip: 3;
        """
        return 'skip', ':', NUMBER, ';'

    def regex():
        """
            regex:"foo";
        """
        return 'regex', ':', QUOTED_STRING, ';'

    def option():
        """ Any of the sub methods, match, skip, regex, side, or state """
        return [match, skip, regex, side, state]

    def rule_type():
        """ Either 'alert', 'block', or 'admit' methods """
        return ['alert', 'block', 'admit']

    def rule():
        """ Define a rule as:
            The rule type, parens, the rule name, many options, and close paren
        """
        return rule_type, '(', name, Parser.AT_LEAST_ONE, option, Parser.OPTIONAL, flush, ')'

    parser = Parser(rule, COMMENT)
    return parser


def main():
    """
    A sample usage of ids_parser()
    """

    import pprint
    printer = pprint.PrettyPrinter(indent=4)
    parser = ids_parser()
    rules = []
    with open(sys.argv[1], 'r') as rules_fh:
        for line in rules_fh.readlines():
            try:
                result = parser.parse(line)
            except SyntaxError as error:
                print "invalid rule, %s : original rule: %s" % (error,
                                                                repr(line))
            if len(result):
                rules.append(result)

    printer.pprint(rules)

if __name__ == '__main__':
    main()

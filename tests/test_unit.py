import unittest
from mureq import _check_redirect, _prepare_incoming_headers, Response, HTTPMessage, HTTPErrorStatus

class RedirectTestCase(unittest.TestCase):

    def test_200(self):
        self.assertEqual(_check_redirect('https://www.google.com/', 200, {'Location': 'https://www.bing.com'}), None)

    def test_302_no_header(self):
        self.assertEqual(_check_redirect('https://www.google.com/', 302, {'X-Location': 'https://www.google.com/search'}), None)

    def test_302_absolute(self):
        self.assertEqual(_check_redirect('https://www.google.com/', 302, {'Location': 'https://www.google.com/search'}), 'https://www.google.com/search')

    def test_301_absolute(self):
        self.assertEqual(_check_redirect('https://www.google.com/', 301, {'Location': 'https://www.google.com/search'}), 'https://www.google.com/search')

    def test_304(self):
        self.assertEqual(_check_redirect('https://www.google.com/', 304, {'Location': 'https://www.google.com/search'}), None)

    def test_302_relative_slash(self):
        self.assertEqual(_check_redirect('https://www.google.com/', 302, {'Location': '/search'}), 'https://www.google.com/search')
        self.assertEqual(_check_redirect('https://www.google.com/baz', 302, {'Location': '/search'}), 'https://www.google.com/search')
        self.assertEqual(_check_redirect('https://www.google.com/baz/', 302, {'Location': '/search'}), 'https://www.google.com/search')

    def test_302_relative_noslash(self):
        self.assertEqual(_check_redirect('https://www.google.com/', 302, {'Location': 'search'}), 'https://www.google.com/search')
        self.assertEqual(_check_redirect('https://www.google.com/baz', 302, {'Location': 'search'}), 'https://www.google.com/search')
        self.assertEqual(_check_redirect('https://www.google.com/baz/', 302, {'Location': 'search'}), 'https://www.google.com/baz/search')
        self.assertEqual(_check_redirect('https://www.google.com/baz/', 302, {'Location': 'search/'}), 'https://www.google.com/baz/search/')
        self.assertEqual(_check_redirect('https://www.google.com/baz/qux', 302, {'Location': 'search/'}), 'https://www.google.com/baz/search/')


class ReponseTestCase(unittest.TestCase):

    def test_ok(self):
        self.assertEqual(Response('', 200, HTTPMessage(), HTTPMessage(), b'').ok, True)
        self.assertEqual(Response('', 204, HTTPMessage(), HTTPMessage(), b'').ok, True)
        self.assertEqual(Response('', 301, HTTPMessage(), HTTPMessage(), b'').ok, True)
        self.assertEqual(Response('', 400, HTTPMessage(), HTTPMessage(), b'').ok, False)
        self.assertEqual(Response('', 404, HTTPMessage(), HTTPMessage(), b'').ok, False)
        self.assertEqual(Response('', 418, HTTPMessage(), HTTPMessage(), b'').ok, False)
        self.assertEqual(Response('', 500, HTTPMessage(), HTTPMessage(), b'').ok, False)
        self.assertEqual(Response('', 504, HTTPMessage(), HTTPMessage(), b'').ok, False)

    def _assert_raises_for_status(self, code):
        resp = Response('', code, HTTPMessage(), HTTPMessage(), b'')
        try:
            resp.raise_for_status()
        except HTTPErrorStatus as e:
            self.assertEqual(e.status_code, code)
        else:
            raise AssertionError("did not raise for status", code)

    def _assert_does_not_raise_for_status(self, code):
        resp = Response('', code, HTTPMessage(), HTTPMessage(), b'')
        resp.raise_for_status()

    def test_raise_for_status(self):
        self._assert_raises_for_status(400)
        self._assert_raises_for_status(401)
        self._assert_raises_for_status(500)
        self._assert_raises_for_status(504)

        self._assert_does_not_raise_for_status(200)
        self._assert_does_not_raise_for_status(204)
        self._assert_does_not_raise_for_status(301)
        self._assert_does_not_raise_for_status(307)


def _make_message(*pairs):
    """Build an HTTPMessage from (name, value) pairs, preserving duplicates."""
    msg = HTTPMessage()
    for k, v in pairs:
        msg[k] = v
    return msg


class PrepareIncomingHeadersTestCase(unittest.TestCase):

    def test_empty(self):
        result = _prepare_incoming_headers(HTTPMessage())
        self.assertEqual(list(result.items()), [])

    def test_single_header(self):
        msg = _make_message(('Content-Type', 'text/html'))
        result = _prepare_incoming_headers(msg)
        self.assertEqual(result['Content-Type'], 'text/html')
        self.assertEqual(len(result.items()), 1)

    def test_multiple_distinct_headers(self):
        msg = _make_message(('Content-Type', 'text/html'), ('Content-Length', '42'))
        result = _prepare_incoming_headers(msg)
        self.assertEqual(result['Content-Type'], 'text/html')
        self.assertEqual(result['Content-Length'], '42')
        self.assertEqual(len(result.items()), 2)

    def test_duplicate_headers_same_case_joined(self):
        msg = _make_message(('Set-Cookie', 'a=1'), ('Set-Cookie', 'b=2'))
        result = _prepare_incoming_headers(msg)
        self.assertEqual(result['Set-Cookie'], 'a=1, b=2')
        self.assertEqual(len(result.items()), 1)

    def test_duplicate_headers_different_case_joined(self):
        # Case-insensitive deduplication: both entries should be merged
        msg = _make_message(('X-Custom', 'first'), ('x-custom', 'second'))
        result = _prepare_incoming_headers(msg)
        self.assertEqual(result['X-Custom'], 'first, second')
        self.assertEqual(len(result.items()), 1)

    def test_original_casing_preserved(self):
        # When all occurrences share the same casing, that casing is preserved
        msg = _make_message(('X-My-Header', 'v1'), ('X-My-Header', 'v2'))
        result = _prepare_incoming_headers(msg)
        keys = [k for k, _ in result.items()]
        self.assertEqual(keys, ['X-My-Header'])

    def test_three_duplicates_joined(self):
        msg = _make_message(('Link', '<a>; rel=next'), ('Link', '<b>; rel=prev'), ('Link', '<c>; rel=first'))
        result = _prepare_incoming_headers(msg)
        self.assertEqual(result['Link'], '<a>; rel=next, <b>; rel=prev, <c>; rel=first')
        self.assertEqual(len(result.items()), 1)

    def test_insertion_order_preserved(self):
        msg = _make_message(('Z-Header', 'z'), ('A-Header', 'a'), ('M-Header', 'm'))
        result = _prepare_incoming_headers(msg)
        keys = [k for k, _ in result.items()]
        self.assertEqual(keys, ['Z-Header', 'A-Header', 'M-Header'])

    def test_returns_httpmessage(self):
        result = _prepare_incoming_headers(HTTPMessage())
        self.assertIsInstance(result, HTTPMessage)

    def test_lookup_is_case_insensitive(self):
        # HTTPMessage supports case-insensitive lookup
        msg = _make_message(('Content-Type', 'application/json'))
        result = _prepare_incoming_headers(msg)
        self.assertEqual(result['content-type'], 'application/json')
        self.assertEqual(result['CONTENT-TYPE'], 'application/json')


if __name__ == '__main__':
    unittest.main()  # pragma: no cover

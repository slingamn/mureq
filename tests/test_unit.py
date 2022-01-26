import unittest
from mureq import _check_redirect, Response, HTTPMessage, HTTPErrorStatus

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
        self.assertEqual(Response('', 200, HTTPMessage(), b'').ok, True)
        self.assertEqual(Response('', 204, HTTPMessage(), b'').ok, True)
        self.assertEqual(Response('', 301, HTTPMessage(), b'').ok, True)
        self.assertEqual(Response('', 400, HTTPMessage(), b'').ok, False)
        self.assertEqual(Response('', 404, HTTPMessage(), b'').ok, False)
        self.assertEqual(Response('', 418, HTTPMessage(), b'').ok, False)
        self.assertEqual(Response('', 500, HTTPMessage(), b'').ok, False)
        self.assertEqual(Response('', 504, HTTPMessage(), b'').ok, False)

    def _assert_raises_for_status(self, code):
        resp = Response('', code, HTTPMessage(), b'')
        try:
            resp.raise_for_status()
        except HTTPErrorStatus as e:
            self.assertEqual(e.status_code, code)
        else:
            raise AssertionError("did not raise for status", code)

    def _assert_does_not_raise_for_status(self, code):
        resp = Response('', code, HTTPMessage(), b'')
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


if __name__ == '__main__':
    unittest.main()  # pragma: no cover

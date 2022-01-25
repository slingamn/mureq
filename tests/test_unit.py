import json
import unittest
from http.client import HTTPException

from mureq import _check_redirect, Response, HTTPMessage

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

    # noinspection PyMethodMayBeStatic
    def test_raise_for_status_good(self):
        resp = Response('', 201, HTTPMessage(), b"We're all OK")
        resp.raise_for_status()

    def test_raise_for_status_bad(self):
        resp = Response('', 502, HTTPMessage(), b"It's going down")
        with self.assertRaises(HTTPException):
            resp.raise_for_status()

    def test_json_good(self):
        resp = Response('', 200, HTTPMessage(), b'{"data": 722}')
        data = resp.json()

        self.assertEqual(data['data'], 722)

    def test_json_bad_response(self):
        resp = Response('', 200, HTTPMessage(), b'THIS IS NOT JSON')

        with self.assertRaises(json.decoder.JSONDecodeError):
            resp.json()


if __name__ == '__main__':
    unittest.main()  # pragma: no cover

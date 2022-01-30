"""
Integration tests for mureq.

These tests depend on third-party infrastructure and MUST NOT be run in an
automated CI setting.
"""

import contextlib
import json
import unittest
import socket
import threading
import tempfile
import os.path
import urllib.parse
import ssl
import http.client
import http.server

import mureq


class MureqIntegrationTestCase(unittest.TestCase):

    def _get_json(self, response):
        # helper for httpbin endpoints
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.ok, True)
        self.assertTrue(response.body is response.content)
        result = json.loads(response.body)
        self.assertEqual(result['headers']['Host'], ['httpbingo.org'])
        return result

    def test_get(self):
        result = self._get_json(mureq.get('https://httpbingo.org/get'))
        self.assertEqual(result['headers']['User-Agent'], [mureq.DEFAULT_UA])
        self.assertEqual(result['url'], 'https://httpbingo.org/get')

    def test_get_http(self):
        result = self._get_json(mureq.get('http://httpbingo.org/get'))
        self.assertEqual(result['headers']['User-Agent'], [mureq.DEFAULT_UA])
        self.assertEqual(result['url'], 'http://httpbingo.org/get')

    def test_headers(self):
        result = self._get_json(mureq.get('https://httpbingo.org/get',
            headers={'User-Agent': 'xyzzy', 'X-Test-Header': 'plugh'}))
        self.assertEqual(result['url'], 'https://httpbingo.org/get')
        self.assertEqual(result['headers']['User-Agent'], ['xyzzy'])
        self.assertEqual(result['headers']['X-Test-Header'], ['plugh'])

    def test_headers_list(self):
        headers = [
            ('X-Test-Header-1', '1'),
            ('X-Test-Header-2', '2'),
            ('X-Test-Header-3', '3'),
            ('X-Test-Header-4', '4'),
        ]
        result = self._get_json(mureq.get('https://httpbingo.org/get', headers=headers))
        for k, v in headers:
            self.assertEqual(result['headers'][k], [v])

    def test_request(self):
        result = self._get_json(mureq.request('GET', 'https://httpbingo.org/get', timeout=10.0))
        self.assertEqual(result['headers']['User-Agent'], [mureq.DEFAULT_UA])
        self.assertEqual(result['url'], 'https://httpbingo.org/get')

    def test_yield_response(self):
        with mureq.yield_response('GET', 'https://httpbingo.org/get') as response:
            # should yield the stdlib type
            self.assertEqual(type(response), http.client.HTTPResponse)
            self.assertEqual(response.status, 200)
            self.assertEqual(response.url, 'https://httpbingo.org/get')
            self.assertEqual(json.loads(response.read())['url'], 'https://httpbingo.org/get')

    def test_bad_method(self):
        response = mureq.post('https://httpbingo.org/get')
        self.assertEqual(response.status_code, 405)
        self.assertEqual(response.ok, False)

        response = mureq.request('PATCH', 'https://httpbingo.org/post', body=b'1')
        self.assertEqual(response.status_code, 405)
        self.assertEqual(response.ok, False)

    def test_query_params(self):
        result = self._get_json(mureq.get('https://httpbingo.org/get'))
        self.assertEqual(result['url'], 'https://httpbingo.org/get')
        self.assertEqual(result['args'], {})

        result = self._get_json(mureq.get('https://httpbingo.org/get?a=b'))
        self.assertEqual(result['url'], 'https://httpbingo.org/get?a=b')
        self.assertEqual(result['args'], {'a': ['b']})

        result = self._get_json(mureq.get('https://httpbingo.org/get', params={'a': 'b'}))
        self.assertEqual(result['url'], 'https://httpbingo.org/get?a=b')
        self.assertEqual(result['args'], {'a': ['b']})

        result = self._get_json(mureq.get('https://httpbingo.org/get?', params={'a': 'b'}))
        self.assertEqual(result['url'], 'https://httpbingo.org/get?a=b')
        self.assertEqual(result['args'], {'a': ['b']})

        result = self._get_json(mureq.get('https://httpbingo.org/get?a=b', params={'c': 'd'}))
        self.assertEqual(result['url'], 'https://httpbingo.org/get?a=b&c=d')
        self.assertEqual(result['args'], {'a': ['b'], 'c': ['d']})

    def test_url_populated(self):
        result = mureq.get('https://httpbingo.org/get?a=b')
        self.assertEqual(result.url, 'https://httpbingo.org/get?a=b')

        result = mureq.get('https://httpbingo.org/get', params={'a': 'b'})
        self.assertEqual(result.url, 'https://httpbingo.org/get?a=b')

        result = mureq.get('https://httpbingo.org/get?c=d', params={'a': 'b'})
        self.assertEqual(result.url, 'https://httpbingo.org/get?c=d&a=b')

    def test_head(self):
        response = mureq.head('https://httpbingo.org/head')
        self.assertIn('Content-Length', response.headers)

    def test_post(self):
        result = self._get_json(mureq.post('https://httpbingo.org/post', body=b'xyz'))
        self.assertEqual(result['headers']['User-Agent'], [mureq.DEFAULT_UA])
        self.assertEqual(result['url'], 'https://httpbingo.org/post')
        self.assertEqual(result['data'], 'xyz')

    def test_put(self):
        result = self._get_json(mureq.put('https://httpbingo.org/put', body=b'strawberry'))
        self.assertEqual(result['headers']['User-Agent'], [mureq.DEFAULT_UA])
        self.assertEqual(result['url'], 'https://httpbingo.org/put')
        self.assertEqual(result['data'], 'strawberry')

    def test_patch(self):
        result = self._get_json(mureq.patch('https://httpbingo.org/patch', body=b'burrito'))
        self.assertEqual(result['headers']['User-Agent'], [mureq.DEFAULT_UA])
        self.assertEqual(result['url'], 'https://httpbingo.org/patch')
        self.assertEqual(result['data'], 'burrito')

    def test_json(self):
        result = self._get_json(mureq.post('https://httpbingo.org/post', json={'a': 1}))
        # we must add the application/json header here
        self.assertEqual(result['headers']['Content-Type'], ['application/json'])
        self.assertEqual(result['json'], {'a': 1})

        obj = {'b': 2}
        result = self._get_json(mureq.post('https://httpbingo.org/post', json=obj,
            headers={'Content-Type': 'application/jose+json'}))
        # we must not override the user-supplied content-type header
        self.assertEqual(result['headers']['Content-Type'], ['application/jose+json'])
        self.assertEqual(json.loads(result['data']), obj)

    def test_form(self):
        result = self._get_json(mureq.post('https://httpbingo.org/post', form={'a': '1'}))
        self.assertEqual(result['headers']['Content-Type'], ['application/x-www-form-urlencoded'])
        self.assertEqual(result['data'], 'a=1')
        # with the correct Content-Type header, test that the body was interpreted as expected:
        self.assertEqual(result['form']['a'], ['1'])

        # we must not override the user-supplied content-type header if it is present:
        result = self._get_json(mureq.post('https://httpbingo.org/post', form={'a': '1'},
            headers={'Content-Type': 'application/jose+json'}))
        self.assertEqual(result['headers']['Content-Type'], ['application/jose+json'])
        self.assertEqual(result['data'], 'a=1')

    def test_redirects(self):
        # redirects us to /get
        response = mureq.get('https://httpbingo.org/redirect/1')
        # by default redirect is not followed
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers['Location'], '/get')
        self.assertEqual(response.url, 'https://httpbingo.org/redirect/1')

        # allow 1 redirect, we should actually retrieve /get
        response = mureq.get('https://httpbingo.org/redirect/1', max_redirects=1)
        # url field should be populated with the retrieved URL
        self.assertEqual(response.url, 'https://httpbingo.org/get')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(json.loads(response.body)['url'], 'https://httpbingo.org/get')
        self.assertEqual(response.url, 'https://httpbingo.org/get')

        # redirect twice, should be disallowed:
        with self.assertRaises(mureq.TooManyRedirects):
            mureq.get('https://httpbingo.org/redirect/2', max_redirects=1)

        response = mureq.get('https://httpbingo.org/redirect/2', max_redirects=2)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(json.loads(response.body)['url'], 'https://httpbingo.org/get')
        self.assertEqual(response.url, 'https://httpbingo.org/get')

        with self.assertRaises(mureq.TooManyRedirects):
            mureq.get('https://httpbingo.org/redirect/3', max_redirects=2)

    def test_307(self):
        response = mureq.get('https://httpbingo.org/redirect-to?url=/get&status_code=307')
        self.assertEqual(response.status_code, 307)
        self.assertEqual(response.headers['Location'], '/get')
        self.assertEqual(response.url, 'https://httpbingo.org/redirect-to?url=/get&status_code=307')

        # 307 should be followed
        response = mureq.get('https://httpbingo.org/redirect-to?url=/get&status_code=307', max_redirects=1)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(json.loads(response.body)['url'], 'https://httpbingo.org/get')
        self.assertEqual(response.url, 'https://httpbingo.org/get')

        # 307 doesn't change the method:
        response = mureq.get('https://httpbingo.org/redirect-to?url=/post&status_code=307', max_redirects=1)
        self.assertEqual(response.status_code, 405)
        self.assertEqual(response.url, 'https://httpbingo.org/post')
        response = mureq.post('https://httpbingo.org/redirect-to?url=/post&status_code=307', body=b'xyz', max_redirects=1)
        self.assertEqual(response.url, 'https://httpbingo.org/post')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(json.loads(response.body)['data'], 'xyz')

    def test_303(self):
        # 303 turns POST into GET
        response = mureq.post('https://httpbingo.org/redirect-to?url=/post&status_code=303', body=b'xyz')
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.url, 'https://httpbingo.org/redirect-to?url=/post&status_code=303')

        response = mureq.post('https://httpbingo.org/redirect-to?url=/post&status_code=303', body=b'xyz', max_redirects=1)
        # now we're trying to GET to /post, which should fail:
        self.assertEqual(response.status_code, 405)
        self.assertEqual(response.url, 'https://httpbingo.org/post')

        response = mureq.post('https://httpbingo.org/redirect-to?url=/get&status_code=303', body=b'xyz', max_redirects=1)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(json.loads(response.body)['url'], 'https://httpbingo.org/get')
        self.assertEqual(response.url, 'https://httpbingo.org/get')

    def test_read_limit(self):
        response = mureq.get('https://httpbingo.org/get', headers={'X-Test-1': 'porcupine'})
        self._get_json(response)
        length = int(response.headers.get('content-length'))
        self.assertEqual(length, len(response.body))

        limit = length//2
        response = mureq.get('https://httpbingo.org/get', headers={'X-Test-1': 'porcupine'}, read_limit=limit)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.body), limit)
        with self.assertRaises(json.JSONDecodeError):
            json.loads(response.body)

    def test_timeout(self):
        result = mureq.get('https://httpbingo.org/delay/1', timeout=5.0)
        self.assertEqual(result.status_code, 200)

        exc = None
        try:
            mureq.get('https://httpbingo.org/delay/2', timeout=1.0)
        except Exception as e:
            exc = e

        self.assertTrue(isinstance(exc, mureq.HTTPException))
        self.assertTrue(isinstance(exc.__cause__, socket.timeout))

def _run_unix_server(sock):
    """Accept loop for a toy http+unix server, to be run in a thread."""
    while True:
        try:
            connection, _ = sock.accept()
        except:
            return
        fileobj = connection.makefile('rb')
        # read all headers
        while fileobj.readline().strip():
            pass
        connection.send(b'HTTP/1.0 204 No Content\r\nDate: Sun, 12 Dec 2021 08:17:16 GMT\r\n\r\n')
        connection.close()

@contextlib.contextmanager
def unix_http_server():
    """Contextmanager providing a http+unix server with its socket in a tmpdir."""
    with tempfile.TemporaryDirectory() as dirpath:
        path = os.path.join(dirpath, 'sock')
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(path)
        sock.listen(1)
        threading.Thread(target=_run_unix_server, args=(sock,)).start()
        try:
            yield path
        finally:
            sock.shutdown(socket.SHUT_RDWR)
            sock.close()

class MureqIntegrationUnixSocketTestCase(unittest.TestCase):

    def test_unix_socket(self):
        with unix_http_server() as unix_socket:
            response = mureq.get('http://localhost', unix_socket=unix_socket)
            self.assertEqual(response.status_code, 204)
            self.assertEqual(response.headers['Date'], 'Sun, 12 Dec 2021 08:17:16 GMT')

            # test unix socket URL convention:
            # quote() has default safe='/', we must explicitly disable that so / is quoted as %2F
            response = mureq.get('http+unix://%s/bar/baz' % (urllib.parse.quote(unix_socket, safe=''),))
            self.assertEqual(response.status_code, 204)
            self.assertEqual(response.headers['Date'], 'Sun, 12 Dec 2021 08:17:16 GMT')


@contextlib.contextmanager
def local_http_server():
    with http.server.ThreadingHTTPServer(('127.0.0.1', 0), http.server.SimpleHTTPRequestHandler) as httpd:
        host, port = httpd.socket.getsockname()[:2]
        try:
            threading.Thread(target=httpd.serve_forever).start()
            yield port
        finally:
            httpd.shutdown()


class MureqIntegrationPortTestCase(unittest.TestCase):

    def test_nonstandard_port(self):
        with local_http_server() as port:
            # test reading the port out of the URL:
            url = 'http://127.0.0.1:%d/' % (port,)
            response = mureq.get(url)
            self.assertEqual(response.status_code, 200)

    def test_source_address(self):
        # TODO implement a local HTTP server that can actually validate
        # the source address; right now this is just a coverage test
        with local_http_server() as port:
            # test reading the port out of the URL:
            url = 'http://127.0.0.1:%d/' % (port,)
            response = mureq.get(url, source_address='127.18.18.18')
            self.assertEqual(response.status_code, 200)


BADSSL_ROOT="""
-----BEGIN CERTIFICATE-----
MIIGfjCCBGagAwIBAgIJAJeg/PrX5Sj9MA0GCSqGSIb3DQEBCwUAMIGBMQswCQYD
VQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5j
aXNjbzEPMA0GA1UECgwGQmFkU1NMMTQwMgYDVQQDDCtCYWRTU0wgVW50cnVzdGVk
IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5MB4XDTE2MDcwNzA2MzEzNVoXDTM2
MDcwMjA2MzEzNVowgYExCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlh
MRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMQ8wDQYDVQQKDAZCYWRTU0wxNDAyBgNV
BAMMK0JhZFNTTCBVbnRydXN0ZWQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkw
ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDKQtPMhEH073gis/HISWAi
bOEpCtOsatA3JmeVbaWal8O/5ZO5GAn9dFVsGn0CXAHR6eUKYDAFJLa/3AhjBvWa
tnQLoXaYlCvBjodjLEaFi8ckcJHrAYG9qZqioRQ16Yr8wUTkbgZf+er/Z55zi1yn
CnhWth7kekvrwVDGP1rApeLqbhYCSLeZf5W/zsjLlvJni9OrU7U3a9msvz8mcCOX
fJX9e3VbkD/uonIbK2SvmAGMaOj/1k0dASkZtMws0Bk7m1pTQL+qXDM/h3BQZJa5
DwTcATaa/Qnk6YHbj/MaS5nzCSmR0Xmvs/3CulQYiZJ3kypns1KdqlGuwkfiCCgD
yWJy7NE9qdj6xxLdqzne2DCyuPrjFPS0mmYimpykgbPnirEPBF1LW3GJc9yfhVXE
Cc8OY8lWzxazDNNbeSRDpAGbBeGSQXGjAbliFJxwLyGzZ+cG+G8lc+zSvWjQu4Xp
GJ+dOREhQhl+9U8oyPX34gfKo63muSgo539hGylqgQyzj+SX8OgK1FXXb2LS1gxt
VIR5Qc4MmiEG2LKwPwfU8Yi+t5TYjGh8gaFv6NnksoX4hU42gP5KvjYggDpR+NSN
CGQSWHfZASAYDpxjrOo+rk4xnO+sbuuMk7gORsrl+jgRT8F2VqoR9Z3CEdQxcCjR
5FsfTymZCk3GfIbWKkaeLQIDAQABo4H2MIHzMB0GA1UdDgQWBBRvx4NzSbWnY/91
3m1u/u37l6MsADCBtgYDVR0jBIGuMIGrgBRvx4NzSbWnY/913m1u/u37l6MsAKGB
h6SBhDCBgTELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNV
BAcMDVNhbiBGcmFuY2lzY28xDzANBgNVBAoMBkJhZFNTTDE0MDIGA1UEAwwrQmFk
U1NMIFVudHJ1c3RlZCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eYIJAJeg/PrX
5Sj9MAwGA1UdEwQFMAMBAf8wCwYDVR0PBAQDAgEGMA0GCSqGSIb3DQEBCwUAA4IC
AQBQU9U8+jTRT6H9AIFm6y50tXTg/ySxRNmeP1Ey9Zf4jUE6yr3Q8xBv9gTFLiY1
qW2qfkDSmXVdBkl/OU3+xb5QOG5hW7wVolWQyKREV5EvUZXZxoH7LVEMdkCsRJDK
wYEKnEErFls5WPXY3bOglBOQqAIiuLQ0f77a2HXULDdQTn5SueW/vrA4RJEKuWxU
iD9XPnVZ9tPtky2Du7wcL9qhgTddpS/NgAuLO4PXh2TQ0EMCll5reZ5AEr0NSLDF
c/koDv/EZqB7VYhcPzr1bhQgbv1dl9NZU0dWKIMkRE/T7vZ97I3aPZqIapC2ulrf
KrlqjXidwrGFg8xbiGYQHPx3tHPZxoM5WG2voI6G3s1/iD+B4V6lUEvivd3f6tq7
d1V/3q1sL5DNv7TvaKGsq8g5un0TAkqaewJQ5fXLigF/yYu5a24/GUD783MdAPFv
gWz8F81evOyRfpf9CAqIswMF+T6Dwv3aw5L9hSniMrblkg+ai0K22JfoBcGOzMtB
Ke/Ps2Za56dTRoY/a4r62hrcGxufXd0mTdPaJLw3sJeHYjLxVAYWQq4QKJQWDgTS
dAEWyN2WXaBFPx5c8KIW95Eu8ShWE00VVC3oA4emoZ2nrzBXLrUScifY6VaYYkkR
2O2tSqU8Ri3XRdgpNPDWp8ZL49KhYGYo3R/k98gnMHiY5g==
-----END CERTIFICATE-----
"""

class MureqIntegrationBadSSLTestCase(unittest.TestCase):

    def test_ssl(self):
        self._check_bad_ssl('https://expired.badssl.com/')
        self._check_bad_ssl('https://wrong.host.badssl.com/')
        self._check_bad_ssl('https://self-signed.badssl.com/')
        self._check_bad_ssl('https://untrusted-root.badssl.com/')

        # whether this is detectable will depend on the age of the ca-certificates
        # package. Python doesn't have OCSP support: https://bugs.python.org/issue17123
        #self._check_bad_ssl('https://revoked.badssl.com/')
        #self._check_bad_ssl('https://pinning-test.badssl.com/')

    def _check_bad_ssl(self, badurl):
        # validation should fail with default arguments
        with self.assertRaises(mureq.HTTPException):
            response = mureq.get(badurl)
        # and succeed with verify=False
        response = mureq.get(badurl, verify=False)
        self.assertEqual(response.status_code, 200)

    def test_ssl_context(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cadata=BADSSL_ROOT)

        response = mureq.get("https://untrusted-root.badssl.com", ssl_context=context)
        self.assertEqual(response.status_code, 200)

        with self.assertRaises(mureq.HTTPException):
            mureq.get("https://httpbingo.org", ssl_context=context)


class MureqIntegrationExceptionTestCase(unittest.TestCase):

    def _check_raises(self, url):
        with self.assertRaises(mureq.HTTPException):
            mureq.get(url, timeout=0.25)

    def test_exceptions(self):
        # all of these should raise a normal HTTPException
        self._check_raises('http://127.0.0.1:48373')
        self._check_raises('http://192.168.22.122:48373')
        self._check_raises('http://10.32.34.58:48373')
        self._check_raises('http://[fe80::fc54:ff:fe94:ed50]:48373')
        self._check_raises('http://%2Ftmp%2Fnonexistent_mureq_sock/')
        # NXDOMAIN:
        self._check_raises('http://mureq.test')
        # blackhole (currently):
        self._check_raises('http://8.8.8.8')
        # refuses connections on port 80 (currently):
        self._check_raises('http://files.stronghold.network')

        with self.assertRaises(mureq.HTTPException):
            mureq.get('http://localhost/', unix_socket='/tmp/nonexistent_mureq_sock')


def _resolve_name(hostname, desired_family=socket.AF_INET6):
    for (family, type_, proto, canonname, sockaddr) in socket.getaddrinfo(hostname, None):
        if family == desired_family:
            return sockaddr[0]
    raise ValueError("couldn't resolve", family, hostname)


class MureqIntegrationIPAddressURLTestCase(unittest.TestCase):

    # TODO : i think this relies on example.com presenting a certificate without
    # requiring SNI. if you substitute httpbingo.org you get:
    # ssl.SSLError: [SSL: TLSV1_ALERT_ACCESS_DENIED] tlsv1 alert access denied (_ssl.c:1131)

    def test_ipv6_url(self):
        addr = _resolve_name('example.com', socket.AF_INET6)
        # ipv6 address must be in brackets
        http_url = 'http://[%s]/' % (addr,)
        http_url_port = 'http://[%s]:80/' % (addr,)
        https_url = 'https://[%s]/' % (addr,)
        https_url_port = 'https://[%s]:443/' % (addr,)

        headers = {'Host': 'example.com'}
        self.assertEqual(mureq.get(http_url, headers=headers).status_code, 200)
        self.assertEqual(mureq.get(http_url_port, headers=headers).status_code, 200)
        self.assertEqual(mureq.get(https_url, headers=headers, verify=False).status_code, 200)
        self.assertEqual(mureq.get(https_url_port, headers=headers, verify=False).status_code, 200)

    def test_ipv4_url(self):
        addr = _resolve_name('example.com', socket.AF_INET)
        http_url = 'http://%s/' % (addr,)
        http_url_port = 'http://%s:80/' % (addr,)
        https_url = 'https://%s/' % (addr,)
        https_url_port = 'https://%s:443/' % (addr,)

        headers = {'Host': 'example.com'}
        self.assertEqual(mureq.get(http_url, headers=headers).status_code, 200)
        self.assertEqual(mureq.get(http_url_port, headers=headers).status_code, 200)
        self.assertEqual(mureq.get(https_url, headers=headers, verify=False).status_code, 200)
        self.assertEqual(mureq.get(https_url_port, headers=headers, verify=False).status_code, 200)


if __name__ == '__main__':
    unittest.main()  # pragma: no cover

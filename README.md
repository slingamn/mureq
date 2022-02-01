mureq
=====

`mureq` is a single-file, zero-dependency alternative to [python-requests](https://github.com/psf/requests), intended to be vendored in-tree by Linux systems software and other lightweight applications. It is released under the [0BSD license](https://opensource.org/licenses/0BSD) to facilitate this (it can be freely copied without any attribution requirements).

```
>>> mureq.get('https://clients3.google.com/generate_204')
Response(status_code=204)
>>> response = _; response.status_code
204
>>> response.headers['date']
'Sun, 26 Dec 2021 01:56:04 GMT'
>>> response.body
b''
>>> params={'snap': 'certbot', 'interface': 'content'}
>>> response = mureq.get('http://snapd/v2/connections', params=params, unix_socket='/run/snapd.socket')
>>> response.status_code
200
>>> response.headers['Content-type']
'application/json'
>>> response.body
b'{"type":"sync","status-code":200,"status":"OK","result":{"established":[],"plugs":[],"slots":[]}}'
>>> response.json()
{'type': 'sync', 'status-code': 200, 'status': 'OK', 'result': {'established': [], 'plugs': [], 'slots': []}}
```

## Why?

In short: performance (memory consumption), security (resilience to supply-chain attacks), and simplicity.

### Performance

python-requests is extremely memory-hungry, mainly due to large transitive dependencies like [chardet](https://github.com/chardet/chardet) that are not needed by typical consumers. Here's a simple benchmark using Python 3.9.7, as packaged by Ubuntu 21.10 for amd64:

```
user@impish:~$ python3 -c "import os; os.system('grep VmRSS /proc/' + str(os.getpid()) + '/status')"
VmRSS:      7404 kB
user@impish:~$ python3 -c "import os, mureq; os.system('grep VmRSS /proc/' + str(os.getpid()) + '/status')"
VmRSS:     13304 kB
user@impish:~$ python3 -c "import os, mureq; mureq.get('https://www.google.com'); os.system('grep VmRSS /proc/' + str(os.getpid()) + '/status')"
VmRSS:     15872 kB
user@impish:~$ python3 -c "import os, requests; os.system('grep VmRSS /proc/' + str(os.getpid()) + '/status')"
VmRSS:     21488 kB
user@impish:~$ python3 -c "import os, requests; requests.get('https://www.google.com'); os.system('grep VmRSS /proc/' + str(os.getpid()) + '/status')"
VmRSS:     24352 kB
```

In terms of the time cost of HTTP requests, any differences between mureq and python-requests should be negligible, except in the case of workloads that use the connection pooling functionality of python-requests. Since mureq opens and closes a new connection for each request, migrating such a workload will incur a performance penalty. Note, however, that the normal python-requests API (`requests.request`, `requests.get`, etc.) also disables connection pooling, [instead closing the socket immediately to prevent accidental resource leaks](https://github.com/psf/requests/blob/a1a6a549a0143d9b32717dbe3d75cd543ae5a4f6/requests/api.py#L57-L61). In order to use connection pooling, you must explicitly create and manage a [requests.Session](https://docs.python-requests.org/en/latest/user/advanced/#session-objects) object.

It's unclear to me whether connection pooling even makes sense in the typical Python context (single-threaded synchronous I/O, where there's no guarantee that the thread of control will re-enter the connection pool). It is much easier to implement this correctly in [Go](https://pkg.go.dev/net/http#Client).

### Security

Together with its transitive dependencies, python-requests is tens of thousands of lines of third-party code that cannot feasibly be audited. The most common way of distributing python-requests and its dependencies is [pypi.org](https://pypi.org/), which has relatively weak security properties: as of late 2021 it supports [hash pinning, but not code signing](https://flawed.net.nz/2021/02/02/PyPI-Security-State/). Typical Python deployments with third-party dependencies are vulnerable to [supply-chain attacks](https://en.wikipedia.org/wiki/Supply_chain_attack) against pypi.org, i.e., compromises of user credentials on pypi.org (or of pypi.org itself) that allow the introduction of malicious code into their dependencies.

In contrast, mureq is approximately 350 lines of code that can be audited easily and included directly in a project. Since mureq's functionality is limited in scope, you should be able to "install" it and forget about it.

### Simplicity

python-requests was an essential addition to the ecosystem when it was created in 2011, but that time is past, and now in many cases the additional complexity it introduces is no longer justified:

1. The standard library has caught up to python-requests in many respects. The most important change is [PEP 476](https://www.python.org/dev/peps/pep-0476/), which began validating TLS certificates by default against the system trust store. This change has landed in every version of Python that still receives security updates.
1. Large portions of python-requests are now taken up with compatibility shims that cover EOL versions of Python, or that preserve compatibility with deprecated versions of the library itself.
1. python-requests and urllib3 have never actually handled the low-level HTTP mechanics specified in [RFC 7230](https://datatracker.ietf.org/doc/html/rfc7230) and its predecessors; this has always been deferred to the standard library ([http.client](https://docs.python.org/3/library/http.client.html) in Python 3, [httplib](https://docs.python.org/2/library/httplib.html) in Python 2). This is why it's so easy to reimplement the core functionality of python-requests in a small amount of code.

However, the API design of python-requests is excellent and in my opinion still considerably superior to that of [urllib.request](https://docs.python.org/3/library/urllib.request.html) --- hence the case for a lightweight third-party library with a requests-like API.

## How?

### How do I install mureq?

mureq supports Python 3.6 and higher. Copy `mureq.py` into a suitable directory of your project, then import as you would any other internal module, e.g. `import .mureq` or `import bar.baz.mureq`.

Supply-chain attacks are considerably mitigated simply by vendoring mureq (i.e. copying it into your tree). If you are also concerned about future attacks on this GitHub account (or GitHub itself), tagged releases of mureq will be signed with the GPG key `0x740FC947B135E7627D4D00F21996B89DF018DCAB` (expires 2025-07-28), or some future key in a chain of trust from it.

Vendoring mureq's tests is not recommended. The tests rely on third-party HTTP services, so including them in a project-specific test suite or CI/CD pipeline will reduce the reliability of your project's tests and also risks overburdening the third-party services.

### How do I use mureq?

The core API (`mureq.get`, `mureq.post`, `mureq.request`, etc.) is similar to python-requests, with a few differences. For now, see the docstrings in `mureq.py` itself for documentation. HTML documentation will be released later if there's a demand for it.

If you're switching from python-requests, there are a few things to keep in mind:

1. `mureq.get`, `mureq.post`, and `mureq.request` mostly work like the [analogous python-requests calls](https://docs.python-requests.org/en/latest/user/quickstart/#make-a-request).
1. The response type is `mureq.HTTPResponse`, which exposes fewer methods and properties than `requests.Response`. In particular, it does not have `text` (since mureq doesn't do any encoding detection). Instead, the response body is in the `body` member, which is always of type `bytes`. (For the sake of compatibility, the `content` property is provided as an alias for `body`.)
1. The default way to send a POST body is with the `body` kwarg, which only accepts `bytes`.
1. The `json` kwarg takes an arbitrary object, which is serialized to JSON, encoded as UTF-8, and sent as the request body with the usual `Content-Type: application/json` header.
1. To send a form-encoded POST body, use the `form` kwarg. This accepts a dictionary of key-value pairs, or any object that can be serialized by [urllib.parse.urlencode](https://docs.python.org/3/library/urllib.parse.html#urllib.parse.urlencode). It will add the usual `Content-Type: application/x-www-form-urlencoded` header.
1. To make a request without reading the entire body at once, use `with mureq.yield_response(url, method, **kwargs)`. This yields a [http.client.HTTPResponse](https://docs.python.org/3/library/http.client.html#httpresponse-objects). Exiting the contextmanager automatically closes the socket.
1. mureq does not follow HTTP redirections by default. To enable them, use the kwarg `max_redirects`, which takes an integer number of redirects to allow, e.g. `max_redirects=2`.
1. mureq will throw a subclass of `mureq.HTTPException` (which is actually just [http.client.HTTPException](https://docs.python.org/3/library/http.client.html#http.client.HTTPException)) for any runtime I/O error (including invalid HTTP responses, connection failures, timeouts, and exceeding the redirection limit). It may throw other exceptions (in particular `ValueError`) for programming errors, such as invalid or inconsistent arguments.
1. mureq supports two ways of making HTTP requests over a Unix domain stream socket:
    - The `unix_socket` kwarg, which overrides the hostname in the URL, e.g. `mureq.get('http://snapd/', unix_socket='/run/snapd.socket')`
    - The `http+unix` URL scheme, which take the percent-encoded path as the hostname, e.g. `http+unix://%2Frun%2Fsnapd.socket/` to connect to `/run/snapd.socket`.

## Who?

If I were you, I would be asking: given that python-requests is used successfully on millions of systems, who is this person touting a replacement?

I'm nobody special --- not a security expert, not an HTTP protocol expert --- just someone who has been [dealing](https://github.com/psf/requests/issues/520) [with](https://github.com/urllib3/urllib3/pull/87) [problems](https://github.com/kjd/idna/pull/22) [in](https://github.com/kjd/idna/pull/24) [this](https://code.launchpad.net/~slingamn/ssh-import-id/+git/ssh-import-id/+merge/389139) [ecosystem](https://bugs.launchpad.net/ubuntu/+source/apport/+bug/1903605) [for](https://code.launchpad.net/~ddstreet/software-properties/+git/software-properties/+merge/396926) [years](https://github.com/OpenPrinting/system-config-printer/pull/247). That's just the thing: HTTP isn't that hard! HTTP is already safe for humans.

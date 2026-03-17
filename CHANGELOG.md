# Changelog
All notable changes to mureq will be documented in this file.

## [0.3.0] - 2026-03-16

v0.3.0 is the third release of mureq.

### API breaks
* Repeated headers in `Response.headers` are now joined with `, ` instead of `,`, matching the Requests behavior

### Fixed
* Redirect handling of [303 See Other](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/303) now clears the request body

### Added
* Added `Response.raw_headers`, which contains the original unjoined headers as an `http.client.HTTPMessage`. `raw_headers.get_all(header_name)` will retrieve a list of all repeated headers under `header_name`.
* Added type annotations (thanks [@hbmartin](https://github.com/hbmartin)!)

## [0.2.0] - 2022-02-03

v0.2.0 is the second release of mureq.

### API breaks
* `json` kwarg now accepts an arbitrary object to be serialized as JSON (matching the Requests behavior), instead of already-serialized JSON

### Added
* Added `raise_for_status()` and `json()` methods to the `Response` type, increasing API compatibility with Requests (#2, #4, thanks [@mikeckennedy](https://github.com/mikeckennedy)!)

## [0.1.0] - 2022-01-17

v0.1.0 was the first release of mureq.

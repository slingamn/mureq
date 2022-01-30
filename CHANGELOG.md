# Changelog
All notable changes to mureq will be documented in this file.

## [0.2.0] - 2022-FIXME-FIXME

v0.2.0 is the second release of mureq.

### API breaks
* `json` kwarg now accepts an arbitrary object to be serialized as JSON (matching the Requests behavior), instead of already-serialized JSON

### Added
* Added `raise_for_status()` and `json()` methods to the `Response` type, increasing API compatibility with Requests (#2, #4, thanks [@mikeckennedy](https://github.com/mikeckennedy)!)

## [0.1.0] - 2022-01-17

v0.1.0 was the first release of mureq.

# Changelog

## 0.2.0 (2024-01-13)

### Added

* Make the addon compatible with other addons that modify the request URL or headers
	* mitmwzl should run before those addons for it to work properly
* Add functionality for matching paths that should be universally skipped, such as Cloudflare's `/cdn-cgi/` path prefix

### Changed

* Switch from a polling-based approach to asyncio futures for waiting on sourcemap subrequest

## 0.1.1 (2024-01-07)

### Added

* Add a 10 second timeout on sourcemap fetches
* Add a 500 ms delay between fetching JS chunks

### Changed

* Change the jswzl API request timeout from 10 to 60 seconds

## 0.1.0 (2024-01-06)

### Added

* Initial release

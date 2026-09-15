Nmap [![Build Status](https://github.com/nmap/nmap/actions/workflows/build.yml/badge.svg)](https://github.com/nmap/nmap/actions/workflows/build.yml)
====

This tree adds to upstream Nmap
------------------------------

* **Native JSON output**, `-oJ <file>`, carrying exactly the same information
  as `-oX` because it mirrors the XML writer rather than duplicating it. NSE
  structured output becomes ordinary JSON objects and arrays instead of nested
  `<table>` and `<elem>` elements. Hosts are written as they finish, so memory
  does not grow with the size of the scan. See [docs/nmap-json.md](docs/nmap-json.md).
* **`--json-lines`**, newline-delimited JSON where every line is a complete
  record. It survives an interrupted scan, can be appended to, and carries task
  and progress events as they happen, so a wrapper can show progress while
  consuming hosts.
* **Two NSE scripts for modern attack surface**: `http-openapi-discover` finds
  exposed OpenAPI/Swagger description documents and reports what they disclose,
  and `http-graphql-introspection` finds GraphQL endpoints and reports whether
  introspection is enabled. Their logic lives in the new `openapi.lua` and
  `graphql.lua` libraries and is covered by unit tests.
* **Fixes found by running the test suites**: `nmap --proxies` with an empty
  element aborted on an assertion instead of reporting bad input, the nsock
  test binary linked against a stale library, `--script-trace` silently dropped
  bytes after every escaped byte, and `log_close()` left a dangling `FILE *`.
* **CI that runs the tests.** The build matrix compiled on fourteen platforms
  but never ran a test; a job now runs the Nmap, nsock and NSE suites plus a
  JSON/XML output equivalence check.

Nmap is released under a custom license, which is based on (but not compatible
with) GPLv2. The Nmap license allows free usage by end users, and we also offer
a commercial license for companies that wish to redistribute Nmap technology
with their products. See [Nmap Copyright and Licensing](https://nmap.org/book/man-legal.html)
for full details.

The latest version of this software as well as binary installers for Windows,
macOS, and Linux (RPM) are available from
[Nmap.org](https://nmap.org/download.html)

Full documentation is also available
[on the Nmap.org website](https://nmap.org/docs.html).

Questions and suggestions may be sent to
[the Nmap-dev mailing list](https://nmap.org/mailman/listinfo/dev).

Installing
----------
Ideally, you should be able to just type:

    ./configure
    make
    make install

For far more in-depth compilation, installation, and removal notes, read the
[Nmap Install Guide](https://nmap.org/book/install.html) on Nmap.org.

Using Nmap
----------
Nmap has a lot of features, but getting started is as easy as running `nmap
scanme.nmap.org`. Running `nmap` without any parameters will give a helpful
list of the most common options, which are discussed in depth in [the man
page](https://nmap.org/book/man.html). Users who prefer a graphical interface
can use the included [Zenmap front-end](https://nmap.org/zenmap/).

Contributing
------------
Information about filing bug reports and contributing to the Nmap project can
be found in the [HACKING](HACKING) and [CONTRIBUTING.md](CONTRIBUTING.md)
files.

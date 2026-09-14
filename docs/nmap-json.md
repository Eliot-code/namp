# Nmap JSON output

`-oJ <file>` writes the results of a scan as JSON. The document carries exactly
the same information as the XML output (`-oX`), because it is produced by
mirroring the XML writer rather than by a separate set of output calls: every
fact Nmap reports already passes through `xml.cc`, and `json.cc` turns that
stream of elements, attributes and text into JSON. Anything that appears in the
XML, including output from NSE scripts, appears in the JSON.

`-oA <basename>` writes `basename.json` alongside the other formats.

    nmap -sV -oJ scan.json scanme.nmap.org
    nmap -sV -oJ - scanme.nmap.org | jq '.hosts[].ports[]'

## Document shape

The top-level object holds the attributes of the XML `<nmaprun>` element
followed by its children:

```json
{
  "scanner": "nmap",
  "args": "nmap -sV -oJ scan.json scanme.nmap.org",
  "start": 1789429172,
  "startstr": "Mon Sep 14 23:39:32 2026",
  "version": "7.98",
  "xmloutputversion": "1.05",
  "scaninfo": [
    { "type": "connect", "protocol": "tcp", "numservices": 1000, "services": "1,3-4,6-7,..." }
  ],
  "verbose": { "level": 0 },
  "debugging": { "level": 0 },
  "hosts": [
    {
      "starttime": 1789429172,
      "endtime": 1789429178,
      "status": { "state": "up", "reason": "syn-ack", "reason_ttl": 52 },
      "addresses": [ { "addr": "45.33.32.156", "addrtype": "ipv4" } ],
      "hostnames": [ { "name": "scanme.nmap.org", "type": "user" } ],
      "ports": [
        {
          "protocol": "tcp",
          "portid": 22,
          "state": { "state": "open", "reason": "syn-ack", "reason_ttl": 52 },
          "service": {
            "name": "ssh",
            "product": "OpenSSH",
            "version": "6.6.1p1 Ubuntu 2ubuntu2.13",
            "method": "probed",
            "conf": 10,
            "cpe": [ "cpe:/a:openbsd:openssh:6.6.1p1", "cpe:/o:linux:linux_kernel" ]
          }
        }
      ],
      "times": { "srtt": 168000, "rttvar": 3000, "to": 180000 }
    }
  ],
  "runstats": {
    "finished": { "time": 1789429178, "elapsed": 6.21, "exit": "success" },
    "hosts": { "up": 1, "down": 0, "total": 1 }
  }
}
```

`hosts` is always present, even when nothing was scanned, so a consumer can
iterate it without checking first.

## Mapping rules

The mapping is not a mechanical transliteration of the XML; it is designed so
that the result can be queried without special-casing.

### Elements become objects, attributes become members

`<state state="open" reason="syn-ack" reason_ttl="52"/>` becomes
`{"state": "open", "reason": "syn-ack", "reason_ttl": 52}`.

### Repeating elements are always arrays

An element that can appear more than once is an array even when only one
appeared, so a host with a single open port is still `.hosts[0].ports[0]`.
These elements, and the keys they use:

| XML element | JSON key | | XML element | JSON key |
|---|---|---|---|---|
| `host` | `hosts` | | `osmatch` | `osmatches` |
| `port` | `ports` | | `osclass` | `osclasses` |
| `address` | `addresses` | | `osfingerprint` | `osfingerprints` |
| `hostname` | `hostnames` | | `portused` | `portsused` |
| `script` | `scripts` | | `hop` | `hops` |
| `extraports` | `extraports` | | `target` | `targets` |
| `extrareasons` | `extrareasons` | | `hosthint` | `hosthints` |
| `scaninfo` | `scaninfo` | | `taskbegin` | `taskbegin` |
| `cpe` | `cpe` | | `taskend` | `taskend` |
| `output` | `output` | | `taskprogress` | `taskprogress` |

Any other element that unexpectedly repeats is promoted to an array rather than
overwritten, so no data is lost.

### Container elements are transparent

`<hostnames>`, `<ports>` and `<hostscript>` exist only to group their children,
and are removed: their children are lifted into the enclosing object. A port is
`.hosts[0].ports[0]`, not `.hosts[0].ports.port[0]`, and host scripts are
`.hosts[0].scripts[]`.

`<prescript>` and `<postscript>` are transparent too, but their children keep
them apart as `prescripts` and `postscripts` at the top level.

Elements that carry their own attributes stay as objects: `os`, `trace`,
`times`, `runstats`, `status`, `service`, `uptime`, `distance` and the sequence
elements are unchanged.

### NSE structured output becomes ordinary JSON

Scripts can report structured results, which XML represents as nested `<table>`
and `<elem>` elements. In JSON they are turned into the structure they describe
and put under the script's `data` key, next to the human-readable `output`:

```json
{
  "id": "http-methods",
  "output": "\n  Supported Methods: GET HEAD POST OPTIONS",
  "data": { "Supported Methods": [ "GET", "HEAD", "POST", "OPTIONS" ] }
}
```

The rules are:

* a `<table>` whose children have `key` attributes becomes an object;
* a `<table>` whose children have no keys becomes an array;
* a table that mixes both becomes an object, with the unkeyed children
  collected in an array under `_`;
* `<elem>` becomes its text.

A script with no structured output simply has no `data` member.

### Types

Attributes that the DTD declares numeric become JSON numbers:

    accuracy conf count down elapsed end endtime etc highver index level line
    lowver numservices percent port portid reason_ttl remaining responses
    rpcnum rtt rttvar seconds srtt start starttime time to total ttl up value

`timedout` becomes a boolean. Everything else is a string, including `version`
and other values that merely look like numbers. A numeric attribute whose value
is not a valid JSON number keeps its text: traceroute writes `rtt="--"` for a
hop that did not answer, and that stays `"--"`.

Numbers keep the exact spelling Nmap produced (`"elapsed": 0.02`), so a value is
never changed by a round trip through a float formatter.

### Strings

Strings are valid UTF-8. Probe responses and script output are arbitrary bytes,
so any byte sequence that is not well-formed UTF-8 is replaced with U+FFFD
rather than producing a document that a parser would reject. Control characters
are escaped.

## Streaming, and `--json-lines`

Hosts are written as soon as they finish, so the file grows during the scan and
peak memory does not depend on how many hosts are scanned. A scan of a /16
costs no more memory than a scan of a single host.

One JSON document cannot be closed until the scan ends, so a scan that is
killed leaves a truncated document, exactly as `-oX` does. For long scans, or
for feeding another process, use `--json-lines`, which writes newline-delimited
JSON (NDJSON) instead:

```
{"type":"scan","scanner":"nmap","args":"...","start":1789429192,...}
{"type":"host","starttime":1789429192,"status":{"state":"up",...},...}
{"type":"host","starttime":1789429193,"status":{"state":"up",...},...}
{"type":"runstats","finished":{"time":1789429194,...},"hosts":{"up":2,...}}
```

Every line is a complete object with a `type` member, so the output can be
consumed as it is produced, stays valid if the scan is interrupted, and can be
appended to with `--append-output`. Appending is not meaningful for the single
document form, and Nmap warns when `--append-output` is used with it.

## Recipes

Open ports, one per line:

```sh
nmap -oJ - 192.0.2.0/24 |
  jq -r '.hosts[] | .addresses[0].addr as $ip
         | .ports[]? | select(.state.state == "open")
         | "\($ip):\(.portid) \(.service.name // "unknown")"'
```

Everything with an outdated OpenSSH:

```sh
jq -r '.hosts[] | .addresses[0].addr as $ip | .ports[]?
       | select(.service.product == "OpenSSH")
       | "\($ip) \(.service.version)"' scan.json
```

Feed hosts into another tool as they are found:

```sh
nmap --json-lines -oJ - 10.0.0.0/8 |
  jq --unbuffered -r 'select(.type == "host") | .addresses[0].addr' |
  while read -r ip; do process "$ip"; done
```

Results of one script across a scan:

```sh
jq '[.hosts[] | .ports[]?.scripts[]? | select(.id == "ssl-cert") | .data]' scan.json
```

## Compatibility

The JSON output follows the XML output: when a new element or attribute is
added to the XML, it appears in the JSON as well, under the rules above. The
`xmloutputversion` member records the version of the underlying document
format.

`tests/json_xml_equivalence.py` checks, for a range of scan types, that every
value in the XML output is present in the JSON output and that the two agree on
how many hosts, ports and scripts were reported.

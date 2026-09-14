#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Check that Nmap's JSON output (-oJ) carries the same data as its XML output.

The JSON writer mirrors the XML writer, so the two documents produced by a
single scan have to agree.  Rather than reimplementing the XML-to-JSON mapping
here (which would just be the same bug twice), this checks invariants that hold
regardless of how the mapping is spelled:

  * every attribute value and text node in the XML appears somewhere in the
    JSON, so nothing is dropped on the way;
  * the number of hosts, ports, scripts and OS matches is the same in both;
  * the JSON parses, and in --json-lines mode every line parses on its own.

Run it against a built nmap:

    python3 tests/json_xml_equivalence.py ./nmap

It scans 127.0.0.1 only, and only with scan types that do not need root.
"""

import json
import os
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

FAILURES = []
CHECKS = [0]


def check(condition, message):
    CHECKS[0] += 1
    if not condition:
        FAILURES.append(message)
    return condition


def normalize(value):
    """Compare values the way the mapping does: numbers lose their spelling."""
    text = str(value)
    if isinstance(value, bool):
        return "true" if value else "false"
    try:
        number = float(text)
    except ValueError:
        return text
    if number == int(number) and "." not in text and "e" not in text.lower():
        return str(int(number))
    return repr(number)


def xml_scalars(path):
    """Every attribute value and text node in the XML document."""
    tree = ET.parse(path)
    values = []
    for element in tree.iter():
        for value in element.attrib.values():
            values.append(normalize(value))
        if element.text and element.text.strip():
            values.append(normalize(element.text))
    return values


def json_scalars(node, acc):
    """Every scalar in the JSON document."""
    if isinstance(node, dict):
        for value in node.values():
            json_scalars(value, acc)
    elif isinstance(node, list):
        for value in node:
            json_scalars(value, acc)
    elif node is not None:
        acc.append(normalize(node))
    return acc


def count_elements(path, tag):
    return sum(1 for _ in ET.parse(path).iter(tag))


def count_json(node, key, acc=None):
    """Count the objects reachable under a given key, at any depth."""
    if acc is None:
        acc = [0]
    if isinstance(node, dict):
        for name, value in node.items():
            if name == key and isinstance(value, list):
                acc[0] += len(value)
            count_json(value, key, acc)
    elif isinstance(node, list):
        for value in node:
            count_json(value, key, acc)
    return acc[0]


def run_scan(nmap, args, workdir, tag, json_lines=False):
    xml_path = os.path.join(workdir, tag + ".xml")
    json_path = os.path.join(workdir, tag + ".json")
    command = [nmap] + args + ["-oX", xml_path, "-oJ", json_path]
    if json_lines:
        command.append("--json-lines")
    result = subprocess.run(command, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=600)
    if result.returncode != 0:
        print(result.stdout.decode("utf-8", "replace"))
        raise SystemExit("nmap exited %d for: %s" % (result.returncode,
                                                     " ".join(command)))
    return xml_path, json_path


def compare(xml_path, json_path, tag):
    with open(json_path, "r", encoding="utf-8") as handle:
        document = json.load(handle)

    missing = []
    present = set(json_scalars(document, []))
    for value in xml_scalars(xml_path):
        # The XML declaration's own attributes and the stylesheet PI are not
        # part of the scan data.
        if value in ("1.0", "UTF-8", "text/xsl", "nmap.xsl"):
            continue
        if value not in present:
            missing.append(value)

    check(not missing,
          "%s: values in XML but not in JSON: %s" % (tag, missing[:5]))

    for tag_name, key in (("host", "hosts"), ("port", "ports"),
                          ("script", "scripts"), ("osmatch", "osmatches"),
                          ("hostname", "hostnames"), ("address", "addresses")):
        in_xml = count_elements(xml_path, tag_name)
        in_json = count_json(document, key)
        if tag_name == "script":
            # Host scripts and pre/post scripts land under their own keys.
            in_json += count_json(document, "prescripts")
            in_json += count_json(document, "postscripts")
        check(in_xml == in_json,
              "%s: %d <%s> in XML but %d %s in JSON"
              % (tag, in_xml, tag_name, in_json, key))


def compare_lines(json_path, xml_path, tag):
    records = []
    with open(json_path, "r", encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except ValueError as error:
                check(False, "%s: line %d is not valid JSON: %s"
                      % (tag, number, error))
                return

    types = [record.get("type") for record in records]
    check(types[:1] == ["scan"], "%s: first record is %r, want 'scan'"
          % (tag, types[:1]))
    check(types[-1:] == ["runstats"], "%s: last record is %r, want 'runstats'"
          % (tag, types[-1:]))
    check(types.count("host") == count_elements(xml_path, "host"),
          "%s: %d host records, %d <host> elements"
          % (tag, types.count("host"), count_elements(xml_path, "host")))


def main():
    nmap = sys.argv[1] if len(sys.argv) > 1 else "./nmap"
    if not os.path.isfile(nmap) or not os.access(nmap, os.X_OK):
        raise SystemExit("usage: %s /path/to/nmap" % sys.argv[0])

    scans = [
        ("ping", ["-sn", "127.0.0.1"]),
        ("connect", ["-sT", "-p", "1-120", "--reason", "127.0.0.1"]),
        ("two-hosts", ["-sT", "-p", "22,80", "-Pn", "127.0.0.1", "127.0.0.2"]),
        ("service", ["-sT", "-sV", "--version-intensity", "0", "-p", "22,80",
                     "127.0.0.1"]),
        ("scripts", ["-sT", "-p", "22", "--script", "banner", "127.0.0.1"]),
        ("empty", ["-sn", "-Pn", "--script-args", "x=1", "192.0.2.0/30"]),
    ]

    with tempfile.TemporaryDirectory(prefix="nmap-json-test-") as workdir:
        for tag, args in scans:
            xml_path, json_path = run_scan(nmap, args, workdir, tag)
            compare(xml_path, json_path, tag)

        xml_path, json_path = run_scan(
            nmap, ["-sT", "-p", "22,80", "127.0.0.1", "127.0.0.2"],
            workdir, "lines", json_lines=True)
        compare_lines(json_path, xml_path, "lines")

    print("Ran %d checks. %d failures." % (CHECKS[0], len(FAILURES)))
    for failure in FAILURES:
        print("FAIL: %s" % failure)

    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())

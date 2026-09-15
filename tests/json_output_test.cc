/***************************************************************************
 * json_output_test.cc -- Unit tests for Nmap's JSON output (json.cc).      *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *
 * The Nmap Security Scanner is (C) 1996-2026 Nmap Software LLC ("The Nmap
 * Project"). Nmap is also a registered trademark of the Nmap Project.
 *
 * This program is distributed under the terms of the Nmap Public Source
 * License (NPSL). The exact license text applying to a particular Nmap
 * release or source code control revision is contained in the LICENSE
 * file distributed with that version of Nmap or source code control
 * revision. More Nmap copyright/legal information is available from
 * https://nmap.org/book/man-legal.html, and further information on the
 * NPSL license itself can be found at https://nmap.org/npsl/ . This
 * header summarizes some key points from the Nmap license, but is no
 * substitute for the actual license text.
 *
 * Nmap is generally free for end users to download and use themselves,
 * including commercial use. It is available from https://nmap.org.
 *
 * The Nmap license generally prohibits companies from using and
 * redistributing Nmap in commercial products, but we sell a special Nmap
 * OEM Edition with a more permissive license and special features for
 * this purpose. See https://nmap.org/oem/
 *
 * If you have received a written Nmap license agreement or contract
 * stating terms other than these (such as an Nmap OEM license), you may
 * choose to use and redistribute Nmap under those terms instead.
 *
 * The official Nmap Windows builds include the Npcap software
 * (https://npcap.com) for packet capture and transmission. It is under
 * separate license terms which forbid redistribution without special
 * permission. So the official Nmap Windows builds may not be redistributed
 * without special permission (such as an Nmap OEM license).
 *
 * Source is provided to this software because we believe users have a
 * right to know exactly what a program is going to do before they run it.
 * This also allows you to audit the software for security holes.
 *
 * Source code also allows you to port Nmap to new platforms, fix bugs, and
 * add new features. You are highly encouraged to submit your changes as a
 * Github PR or by email to the dev@nmap.org mailing list for possible
 * incorporation into the main distribution. Unless you specify otherwise, it
 * is understood that you are offering us very broad rights to use your
 * submissions as described in the Nmap Public Source License Contributor
 * Agreement. This is important because we fund the project by selling licenses
 * with various terms, and also because the inability to relicense code has
 * caused devastating problems for other Free Software projects (such as KDE
 * and NASM).
 *
 * The free version of Nmap is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. Warranties,
 * indemnification and commercial support are all available through the
 * Npcap OEM program--see https://nmap.org/oem/
 *
 ***************************************************************************/

#include "../json.h"
#include "../output.h"
#include "../NmapOps.h"

#include <stdio.h>
#include <string.h>

#include <iostream>
#include <string>

extern NmapOps o;

static int num_failures = 0;
static int num_tests = 0;

static void check(bool ok, const std::string &what, int line) {
  num_tests++;
  if (!ok) {
    num_failures++;
    std::cout << "FAIL (" << __FILE__ << ":" << line << "): " << what << std::endl;
  }
}

static void check_eq(const std::string &got, const std::string &want, int line) {
  num_tests++;
  if (got != want) {
    num_failures++;
    std::cout << "FAIL (" << __FILE__ << ":" << line << "):" << std::endl
              << "  got  " << got << std::endl
              << "  want " << want << std::endl;
  }
}

#define CHECK(pred) check((pred), #pred, __LINE__)
#define CHECK_EQ(got, want) check_eq((got), (want), __LINE__)

/*--------------------------------------------------------------------------
 * Quoting
 *--------------------------------------------------------------------------*/
static void test_quoting() {
  CHECK_EQ(json_quote("plain"), "\"plain\"");
  CHECK_EQ(json_quote(""), "\"\"");
  CHECK_EQ(json_quote("a\"b"), "\"a\\\"b\"");
  CHECK_EQ(json_quote("a\\b"), "\"a\\\\b\"");
  CHECK_EQ(json_quote("one\ntwo\tthree\r"), "\"one\\ntwo\\tthree\\r\"");
  CHECK_EQ(json_quote(std::string("\x01\x1f", 2)), "\"\\u0001\\u001f\"");
  /* A NUL in the middle of a std::string must not truncate the output. */
  CHECK_EQ(json_quote(std::string("a\0b", 3)), "\"a\\u0000b\"");
  /* Forward slashes need no escaping. */
  CHECK_EQ(json_quote("/usr/bin"), "\"/usr/bin\"");

  /* Well-formed UTF-8 is passed through untouched... */
  CHECK_EQ(json_quote("caf\xc3\xa9"), "\"caf\xc3\xa9\"");
  CHECK_EQ(json_quote("\xe2\x82\xac"), "\"\xe2\x82\xac\"");
  CHECK_EQ(json_quote("\xf0\x9f\x92\xa9"), "\"\xf0\x9f\x92\xa9\"");
  /* ...and anything else is replaced, because probe responses are arbitrary
     bytes but a JSON document has to be valid UTF-8. */
  CHECK_EQ(json_quote("\xff"), "\"\\ufffd\"");
  CHECK_EQ(json_quote("\xc3"), "\"\\ufffd\"");
  CHECK_EQ(json_quote("\xc3\x28"), "\"\\ufffd(\"");
  /* Overlong encoding of '/': both bytes are rejected. */
  CHECK_EQ(json_quote("\xc0\xaf"), "\"\\ufffd\\ufffd\"");
  /* Surrogate half, which is not legal UTF-8. */
  CHECK_EQ(json_quote("\xed\xa0\x80"), "\"\\ufffd\\ufffd\\ufffd\"");
}

/*--------------------------------------------------------------------------
 * Number recognition
 *--------------------------------------------------------------------------*/
static void test_numbers() {
  CHECK(json_is_number("0"));
  CHECK(json_is_number("-0"));
  CHECK(json_is_number("42"));
  CHECK(json_is_number("-17"));
  CHECK(json_is_number("0.02"));
  CHECK(json_is_number("1789429172"));
  CHECK(json_is_number("1e5"));
  CHECK(json_is_number("1.5E-3"));

  CHECK(!json_is_number(""));
  CHECK(!json_is_number("-"));
  CHECK(!json_is_number("--"));
  CHECK(!json_is_number("007"));   /* JSON forbids leading zeros */
  CHECK(!json_is_number("+1"));
  CHECK(!json_is_number("1."));
  CHECK(!json_is_number(".5"));
  CHECK(!json_is_number("0x10"));
  CHECK(!json_is_number("1 "));
  CHECK(!json_is_number(" 1"));
  CHECK(!json_is_number("inf"));
  CHECK(!json_is_number("nan"));
  CHECK(!json_is_number("1e"));
  CHECK(!json_is_number("Good luck!"));
}

/*--------------------------------------------------------------------------
 * Value serialization
 *--------------------------------------------------------------------------*/
static void test_dump() {
  JsonValue obj = JsonValue::make_object();
  JsonValue arr = JsonValue::make_array();

  CHECK_EQ(JsonValue::make_object().dump(-1), "{}");
  CHECK_EQ(JsonValue::make_array().dump(-1), "[]");
  CHECK_EQ(JsonValue::make_null().dump(-1), "null");
  CHECK_EQ(JsonValue::make_bool(true).dump(-1), "true");
  CHECK_EQ(JsonValue::make_bool(false).dump(-1), "false");
  /* Numbers keep the exact text Nmap produced. */
  CHECK_EQ(JsonValue::make_number("0.02").dump(-1), "0.02");

  arr.append(JsonValue::make_number("1"));
  arr.append(JsonValue::make_string("two"));
  obj.set("name", JsonValue::make_string("scan"));
  obj.set("items", arr);

  CHECK_EQ(obj.dump(-1), "{\"name\":\"scan\",\"items\":[1,\"two\"]}");
  CHECK_EQ(obj.dump(2, 0),
           "{\n"
           "  \"name\": \"scan\",\n"
           "  \"items\": [\n"
           "    1,\n"
           "    \"two\"\n"
           "  ]\n"
           "}");
  /* Starting at a deeper level indents everything but the first line. */
  CHECK_EQ(JsonValue::make_array().dump(2, 3), "[]");

  /* set() replaces in place and keeps the original position. */
  obj.set("name", JsonValue::make_string("other"));
  CHECK_EQ(obj.dump(-1), "{\"name\":\"other\",\"items\":[1,\"two\"]}");
}

/*--------------------------------------------------------------------------
 * Element conversion rules
 *--------------------------------------------------------------------------*/
static void test_simple_element() {
  JsonElement port("port");
  JsonElement *state;

  port.add_attribute("protocol", "tcp");
  port.add_attribute("portid", "443");
  state = port.add_child("state");
  state->add_attribute("state", "open");
  state->add_attribute("reason", "syn-ack");
  state->add_attribute("reason_ttl", "64");

  /* portid and reason_ttl are numeric per the DTD; protocol is not. */
  CHECK_EQ(json_convert_element(&port).dump(-1),
           "{\"protocol\":\"tcp\",\"portid\":443,"
           "\"state\":{\"state\":\"open\",\"reason\":\"syn-ack\",\"reason_ttl\":64}}");
}

static void test_arrays_and_containers() {
  JsonElement host("host");
  JsonElement *hostnames, *ports, *port;

  host.add_attribute("starttime", "1789429172");
  host.add_attribute("timedout", "true");

  hostnames = host.add_child("hostnames");
  hostnames->add_child("hostname")->add_attribute("name", "scanme.example");

  ports = host.add_child("ports");
  port = ports->add_child("port");
  port->add_attribute("protocol", "tcp");
  port->add_attribute("portid", "22");

  /* <hostnames> and <ports> are transparent containers, so a single port is
     still hosts[].ports[0] and never hosts[].ports.port. */
  CHECK_EQ(json_convert_element(&host).dump(-1),
           "{\"starttime\":1789429172,\"timedout\":true,"
           "\"hostnames\":[{\"name\":\"scanme.example\"}],"
           "\"ports\":[{\"protocol\":\"tcp\",\"portid\":22}]}");

  CHECK(json_element_is_array("port"));
  CHECK(json_element_is_array("host"));
  CHECK(!json_element_is_array("status"));
  CHECK(json_element_is_transparent("ports"));
  CHECK(!json_element_is_transparent("os"));
  CHECK_EQ(json_key_for_element("osmatch"), "osmatches");
  CHECK_EQ(json_key_for_element("status"), "status");
}

static void test_prescript_key_override() {
  JsonElement run("nmaprun");
  JsonElement *pre, *post;

  pre = run.add_child("prescript");
  pre->add_child("script")->add_attribute("id", "broadcast-ping");
  post = run.add_child("postscript");
  post->add_child("script")->add_attribute("id", "reverse-index");

  /* Both contain <script>, so they need distinct keys to stay apart. */
  CHECK_EQ(json_convert_element(&run).dump(-1),
           "{\"prescripts\":[{\"id\":\"broadcast-ping\"}],"
           "\"postscripts\":[{\"id\":\"reverse-index\"}]}");
}

static void test_text_only_element() {
  JsonElement service("service");
  JsonElement *cpe;

  service.add_attribute("name", "http");
  service.add_attribute("conf", "10");
  cpe = service.add_child("cpe");
  cpe->text = "cpe:/a:apache:http_server:2.4.58";

  CHECK_EQ(json_convert_element(&service).dump(-1),
           "{\"name\":\"http\",\"conf\":10,"
           "\"cpe\":[\"cpe:/a:apache:http_server:2.4.58\"]}");
}

static void test_nse_structured_output() {
  /* A script with keyed children becomes an object. */
  {
    JsonElement script("script");
    JsonElement *elem;

    script.add_attribute("id", "http-title");
    script.add_attribute("output", "Example Domain");
    elem = script.add_child("elem");
    elem->add_attribute("key", "title");
    elem->text = "Example Domain";

    CHECK_EQ(json_convert_element(&script).dump(-1),
             "{\"id\":\"http-title\",\"output\":\"Example Domain\","
             "\"data\":{\"title\":\"Example Domain\"}}");
  }

  /* A table with no keys becomes an array. */
  {
    JsonElement script("script");
    JsonElement *table;

    script.add_attribute("id", "http-methods");
    table = script.add_child("table");
    table->add_attribute("key", "Supported Methods");
    table->add_child("elem")->text = "GET";
    table->add_child("elem")->text = "HEAD";

    CHECK_EQ(json_convert_element(&script).dump(-1),
             "{\"id\":\"http-methods\","
             "\"data\":{\"Supported Methods\":[\"GET\",\"HEAD\"]}}");
  }

  /* Nested tables keep their shape. */
  {
    JsonElement script("script");
    JsonElement *outer, *inner, *elem;

    script.add_attribute("id", "ssl-cert");
    outer = script.add_child("table");
    outer->add_attribute("key", "subject");
    elem = outer->add_child("elem");
    elem->add_attribute("key", "commonName");
    elem->text = "example.com";
    inner = script.add_child("table");
    inner->add_attribute("key", "validity");
    elem = inner->add_child("elem");
    elem->add_attribute("key", "notAfter");
    elem->text = "2027-01-01T00:00:00";

    CHECK_EQ(json_convert_element(&script).dump(-1),
             "{\"id\":\"ssl-cert\",\"data\":{"
             "\"subject\":{\"commonName\":\"example.com\"},"
             "\"validity\":{\"notAfter\":\"2027-01-01T00:00:00\"}}}");
  }

  /* A table that mixes keyed and unkeyed children keeps both. */
  {
    JsonElement script("script");
    JsonElement *table, *elem;

    script.add_attribute("id", "mixed");
    table = script.add_child("table");
    table->add_attribute("key", "results");
    elem = table->add_child("elem");
    elem->add_attribute("key", "state");
    elem->text = "VULNERABLE";
    table->add_child("elem")->text = "extra note";

    CHECK_EQ(json_convert_element(&script).dump(-1),
             "{\"id\":\"mixed\",\"data\":{\"results\":"
             "{\"state\":\"VULNERABLE\",\"_\":[\"extra note\"]}}}");
  }
}

static void test_non_numeric_fallback() {
  JsonElement hop("hop");

  /* Traceroute writes rtt="--" for a hop that did not answer, so a numeric
     attribute that is not a number has to stay a string. */
  hop.add_attribute("ttl", "3");
  hop.add_attribute("rtt", "--");
  CHECK_EQ(json_convert_element(&hop).dump(-1), "{\"ttl\":3,\"rtt\":\"--\"}");

  {
    JsonElement hop2("hop");
    hop2.add_attribute("ttl", "3");
    hop2.add_attribute("rtt", "0.25");
    CHECK_EQ(json_convert_element(&hop2).dump(-1), "{\"ttl\":3,\"rtt\":0.25}");
  }

  {
    /* A version is text even though it looks like a number. */
    JsonElement run("nmaprun");
    run.add_attribute("version", "7.98");
    CHECK_EQ(json_convert_element(&run).dump(-1), "{\"version\":\"7.98\"}");
  }
}

static void test_duplicate_promotion() {
  JsonElement host("host");

  /* <status> is not a repeating element, but if one ever showed up twice the
     second must not overwrite the first. */
  host.add_child("status")->add_attribute("state", "up");
  host.add_child("status")->add_attribute("state", "down");

  CHECK_EQ(json_convert_element(&host).dump(-1),
           "{\"status\":[{\"state\":\"up\"},{\"state\":\"down\"}]}");
}

/*--------------------------------------------------------------------------
 * The streaming writer
 *--------------------------------------------------------------------------*/
static const char *TMPFILE = "json_output_test.tmp";

static std::string read_tmpfile() {
  std::string contents;
  char buf[4096];
  size_t n;
  FILE *fp = fopen(TMPFILE, "rb");

  if (fp == NULL)
    return contents;
  while ((n = fread(buf, 1, sizeof(buf), fp)) > 0)
    contents.append(buf, n);
  fclose(fp);

  return contents;
}

/* Drive the mirror the way xml.cc does for a one-host scan. */
static void emit_sample_document(bool finish) {
  json_mirror_start_element("nmaprun");
  json_mirror_attribute("scanner", "nmap");
  json_mirror_attribute("start", "1789429172");
  json_mirror_attribute("version", "7.98");

  json_mirror_start_element("verbose");
  json_mirror_attribute("level", "0");
  json_mirror_end_element();

  json_mirror_start_element("debugging");
  json_mirror_attribute("level", "0");
  json_mirror_end_element();

  json_mirror_start_element("host");
  json_mirror_start_element("status");
  json_mirror_attribute("state", "up");
  json_mirror_end_element();
  json_mirror_start_element("address");
  json_mirror_attribute("addr", "192.0.2.1");
  json_mirror_attribute("addrtype", "ipv4");
  json_mirror_end_element();
  json_mirror_start_element("ports");
  json_mirror_start_element("port");
  json_mirror_attribute("protocol", "tcp");
  json_mirror_attribute("portid", "80");
  json_mirror_start_element("state");
  json_mirror_attribute("state", "open");
  json_mirror_end_element();
  json_mirror_end_element(); /* port */
  json_mirror_end_element(); /* ports */
  json_mirror_end_element(); /* host */

  json_mirror_start_element("runstats");
  json_mirror_start_element("finished");
  json_mirror_attribute("time", "1789429173");
  json_mirror_attribute("exit", "success");
  json_mirror_end_element();
  json_mirror_end_element(); /* runstats */

  if (finish)
    json_mirror_end_element(); /* nmaprun */
}

static void test_writer_document() {
  std::string out;

  log_open(LOG_JSON, false, TMPFILE);
  json_output_enable(false);
  emit_sample_document(true);
  log_close(LOG_JSON);

  out = read_tmpfile();
  CHECK_EQ(out,
           "{\n"
           "  \"scanner\": \"nmap\",\n"
           "  \"start\": 1789429172,\n"
           "  \"version\": \"7.98\",\n"
           "  \"verbose\": {\n"
           "    \"level\": 0\n"
           "  },\n"
           "  \"debugging\": {\n"
           "    \"level\": 0\n"
           "  },\n"
           "  \"hosts\": [\n"
           "    {\n"
           "      \"status\": {\n"
           "        \"state\": \"up\"\n"
           "      },\n"
           "      \"addresses\": [\n"
           "        {\n"
           "          \"addr\": \"192.0.2.1\",\n"
           "          \"addrtype\": \"ipv4\"\n"
           "        }\n"
           "      ],\n"
           "      \"ports\": [\n"
           "        {\n"
           "          \"protocol\": \"tcp\",\n"
           "          \"portid\": 80,\n"
           "          \"state\": {\n"
           "            \"state\": \"open\"\n"
           "          }\n"
           "        }\n"
           "      ]\n"
           "    }\n"
           "  ],\n"
           "  \"runstats\": {\n"
           "    \"finished\": {\n"
           "      \"time\": 1789429173,\n"
           "      \"exit\": \"success\"\n"
           "    }\n"
           "  }\n"
           "}\n");
}

static void test_writer_lines() {
  std::string out;

  log_open(LOG_JSON, false, TMPFILE);
  json_output_enable(true);
  emit_sample_document(true);
  log_close(LOG_JSON);

  out = read_tmpfile();
  CHECK_EQ(out,
           "{\"type\":\"scan\",\"scanner\":\"nmap\",\"start\":1789429172,"
           "\"version\":\"7.98\",\"verbose\":{\"level\":0},"
           "\"debugging\":{\"level\":0}}\n"
           "{\"type\":\"host\",\"status\":{\"state\":\"up\"},"
           "\"addresses\":[{\"addr\":\"192.0.2.1\",\"addrtype\":\"ipv4\"}],"
           "\"ports\":[{\"protocol\":\"tcp\",\"portid\":80,"
           "\"state\":{\"state\":\"open\"}}]}\n"
           "{\"type\":\"runstats\",\"finished\":{\"time\":1789429173,"
           "\"exit\":\"success\"}}\n");
}

static void test_writer_unterminated() {
  std::string out;

  /* A scan that dies before </nmaprun>: json_output_finish() still has to
     produce a closed document out of whatever was collected. */
  log_open(LOG_JSON, false, TMPFILE);
  json_output_enable(false);
  emit_sample_document(false);
  json_output_finish();
  log_close(LOG_JSON);

  out = read_tmpfile();
  CHECK(out.size() > 0);
  CHECK(out.find("\"hosts\": [") != std::string::npos);
  CHECK(out.find("\"runstats\"") != std::string::npos);
  /* Balanced braces mean the document was closed. */
  {
    size_t opens = 0, closes = 0, i;
    bool in_string = false;
    for (i = 0; i < out.size(); i++) {
      if (in_string) {
        if (out[i] == '\\')
          i++;
        else if (out[i] == '"')
          in_string = false;
        continue;
      }
      if (out[i] == '"')
        in_string = true;
      else if (out[i] == '{')
        opens++;
      else if (out[i] == '}')
        closes++;
    }
    CHECK(opens == closes);
  }
}

static void test_writer_lines_are_live() {
  std::string out;
  size_t task_line, host_line;

  /* Task events must reach the file as they happen rather than being held
     back until the scan ends, so that a consumer can follow a long scan. */
  log_open(LOG_JSON, false, TMPFILE);
  json_output_enable(true);

  json_mirror_start_element("nmaprun");
  json_mirror_attribute("scanner", "nmap");
  json_mirror_start_element("verbose");
  json_mirror_attribute("level", "1");
  json_mirror_end_element();
  json_mirror_start_element("debugging");
  json_mirror_attribute("level", "0");
  json_mirror_end_element();

  json_mirror_start_element("taskbegin");
  json_mirror_attribute("task", "SYN Stealth Scan");
  json_mirror_attribute("time", "1789429172");
  json_mirror_end_element();

  json_mirror_start_element("host");
  json_mirror_start_element("status");
  json_mirror_attribute("state", "up");
  json_mirror_end_element();
  json_mirror_end_element();

  json_mirror_end_element(); /* nmaprun */
  log_close(LOG_JSON);

  out = read_tmpfile();
  task_line = out.find("\"type\":\"taskbegin\"");
  host_line = out.find("\"type\":\"host\"");
  CHECK(task_line != std::string::npos);
  CHECK(host_line != std::string::npos);
  /* The event happened before the host finished, so it is written first. */
  CHECK(task_line < host_line);
  CHECK(out.find("\"task\":\"SYN Stealth Scan\"") != std::string::npos);
}

static void test_writer_ignores_events_after_finish() {
  std::string out;

  /* A fatal error can close the document and then unwind through code that
     keeps writing XML. Those late events must not corrupt the JSON file. */
  log_open(LOG_JSON, false, TMPFILE);
  json_output_enable(false);
  CHECK(json_output_enabled());
  CHECK(!json_output_lines_mode());
  json_output_finish();
  emit_sample_document(true); /* all of this happens after finish */
  json_output_finish();       /* idempotent */
  log_close(LOG_JSON);

  out = read_tmpfile();
  CHECK(out.find("192.0.2.1") == std::string::npos);
  CHECK_EQ(out, "{\n  \"hosts\": []\n}\n");

  json_output_enable(true);
  CHECK(json_output_lines_mode());
  json_output_finish();
}

int main() {
  test_quoting();
  test_numbers();
  test_dump();
  test_simple_element();
  test_arrays_and_containers();
  test_prescript_key_override();
  test_text_only_element();
  test_nse_structured_output();
  test_non_numeric_fallback();
  test_duplicate_promotion();
  test_writer_document();
  test_writer_lines();
  test_writer_lines_are_live();
  test_writer_unterminated();
  test_writer_ignores_events_after_finish();

  remove(TMPFILE);

  std::cout << "Ran " << num_tests << " tests. " << num_failures << " failures."
            << std::endl;

  return num_failures != 0;
}

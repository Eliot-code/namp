/***************************************************************************
 * json.cc -- Streaming JSON output for Nmap.                               *
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

/* $Id$ */

/*
This file implements Nmap's JSON output.  Rather than being a second,
hand-maintained set of output calls that would inevitably drift away from the
XML output, it mirrors the XML writer: xml.cc calls into the json_mirror_*
functions, and this file turns that stream of element/attribute/text events
into a JSON document.  Anything that appears in the XML output therefore
appears in the JSON output, including output from NSE scripts.

The mapping from XML to JSON is not a mechanical one-to-one transliteration,
because the result would be tedious to query.  The rules are:

  * An element becomes a JSON object whose keys are its attributes.
  * Elements that can repeat become arrays with a plural key, so a single open
    port is still .hosts[0].ports[0] rather than sometimes an object and
    sometimes a list.
  * Pure container elements (<hostnames>, <ports>, <hostscript>, <prescript>,
    <postscript>) are transparent: their children are lifted into the parent,
    so a port is .hosts[0].ports[0] and not .hosts[0].ports.ports[0].
  * <table> and <elem>, which NSE scripts use for structured output, are
    turned into natural JSON: keyed children become object members and unkeyed
    children become array items.  This is the part that makes script results
    usable without a second parser.
  * Attributes that the DTD declares numeric become JSON numbers, and
    timedout becomes a boolean.  A value that does not parse as a strict JSON
    number (traceroute writes rtt="--" for a lost hop) stays a string.

Hosts are written as soon as their </host> is seen, so peak memory is bounded
by the largest single host rather than by the size of the scan.
*/

#include "json.h"
#include "output.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

/*==========================================================================
 * JSON value model
 *==========================================================================*/

JsonValue::JsonValue() : t(JSON_NULL), b(false) {
}

JsonValue JsonValue::make_null() {
  return JsonValue();
}

JsonValue JsonValue::make_bool(bool value) {
  JsonValue v;
  v.t = JSON_BOOL;
  v.b = value;
  return v;
}

JsonValue JsonValue::make_number(const std::string &literal) {
  JsonValue v;
  v.t = JSON_NUMBER;
  v.s = literal;
  return v;
}

JsonValue JsonValue::make_string(const std::string &value) {
  JsonValue v;
  v.t = JSON_STRING;
  v.s = value;
  return v;
}

JsonValue JsonValue::make_array() {
  JsonValue v;
  v.t = JSON_ARRAY;
  return v;
}

JsonValue JsonValue::make_object() {
  JsonValue v;
  v.t = JSON_OBJECT;
  return v;
}

void JsonValue::set(const std::string &key, const JsonValue &value) {
  assert(t == JSON_OBJECT);
  for (size_t i = 0; i < obj.size(); i++) {
    if (obj[i].first == key) {
      obj[i].second = value;
      return;
    }
  }
  obj.push_back(std::make_pair(key, value));
}

JsonValue *JsonValue::get(const std::string &key) {
  if (t != JSON_OBJECT)
    return NULL;
  for (size_t i = 0; i < obj.size(); i++) {
    if (obj[i].first == key)
      return &obj[i].second;
  }
  return NULL;
}

const JsonValue *JsonValue::get(const std::string &key) const {
  if (t != JSON_OBJECT)
    return NULL;
  for (size_t i = 0; i < obj.size(); i++) {
    if (obj[i].first == key)
      return &obj[i].second;
  }
  return NULL;
}

void JsonValue::append(const JsonValue &value) {
  assert(t == JSON_ARRAY);
  arr.push_back(value);
}

const JsonValue *JsonValue::at(size_t index) const {
  if (t != JSON_ARRAY || index >= arr.size())
    return NULL;
  return &arr[index];
}

size_t JsonValue::size() const {
  if (t == JSON_ARRAY)
    return arr.size();
  if (t == JSON_OBJECT)
    return obj.size();
  return 0;
}

bool JsonValue::empty() const {
  return size() == 0;
}

static void indent_by(std::string &out, int indent, int level) {
  if (indent <= 0)
    return;
  out.append((size_t) indent * level, ' ');
}

std::string JsonValue::dump(int indent, int level) const {
  std::string out;

  switch (t) {
  case JSON_NULL:
    return "null";
  case JSON_BOOL:
    return b ? "true" : "false";
  case JSON_NUMBER:
    /* Stored as the literal Nmap produced, validated on the way in. */
    return s;
  case JSON_STRING:
    return json_quote(s);
  case JSON_ARRAY:
    if (arr.empty())
      return "[]";
    out = "[";
    for (size_t i = 0; i < arr.size(); i++) {
      if (i > 0)
        out += ",";
      if (indent >= 0) {
        out += "\n";
        indent_by(out, indent, level + 1);
      }
      out += arr[i].dump(indent, level + 1);
    }
    if (indent >= 0) {
      out += "\n";
      indent_by(out, indent, level);
    }
    out += "]";
    return out;
  case JSON_OBJECT:
    if (obj.empty())
      return "{}";
    out = "{";
    for (size_t i = 0; i < obj.size(); i++) {
      if (i > 0)
        out += ",";
      if (indent >= 0) {
        out += "\n";
        indent_by(out, indent, level + 1);
      }
      out += json_quote(obj[i].first);
      out += ":";
      if (indent >= 0)
        out += " ";
      out += obj[i].second.dump(indent, level + 1);
    }
    if (indent >= 0) {
      out += "\n";
      indent_by(out, indent, level);
    }
    out += "}";
    return out;
  }

  return "null";
}

/*==========================================================================
 * String quoting and number validation
 *==========================================================================*/

/* Length of the UTF-8 sequence introduced by this byte, or 0 if the byte
   cannot start one. */
static size_t utf8_seq_len(unsigned char c) {
  if ((c & 0x80) == 0x00)
    return 1;
  if ((c & 0xE0) == 0xC0)
    return 2;
  if ((c & 0xF0) == 0xE0)
    return 3;
  if ((c & 0xF8) == 0xF0)
    return 4;
  return 0;
}

/* Check that s[i..] starts a well-formed, non-overlong UTF-8 sequence of
   length len that encodes a legal code point. */
static bool utf8_seq_valid(const std::string &s, size_t i, size_t len) {
  unsigned long cp;
  size_t k;

  if (i + len > s.size())
    return false;

  cp = (unsigned char) s[i];
  if (len == 2)
    cp &= 0x1F;
  else if (len == 3)
    cp &= 0x0F;
  else if (len == 4)
    cp &= 0x07;

  for (k = 1; k < len; k++) {
    unsigned char c = (unsigned char) s[i + k];
    if ((c & 0xC0) != 0x80)
      return false;
    cp = (cp << 6) | (c & 0x3F);
  }

  /* Reject overlong encodings, surrogates and out-of-range code points. */
  if (len == 2 && cp < 0x80)
    return false;
  if (len == 3 && (cp < 0x800 || (cp >= 0xD800 && cp <= 0xDFFF)))
    return false;
  if (len == 4 && (cp < 0x10000 || cp > 0x10FFFF))
    return false;

  return true;
}

std::string json_quote(const std::string &s) {
  std::string out;
  size_t i;
  char buf[8];

  out.reserve(s.size() + 2);
  out += '"';

  for (i = 0; i < s.size();) {
    unsigned char c = (unsigned char) s[i];
    size_t len;

    if (c == '"') {
      out += "\\\"";
      i++;
      continue;
    }
    if (c == '\\') {
      out += "\\\\";
      i++;
      continue;
    }
    if (c < 0x20) {
      switch (c) {
      case '\b': out += "\\b"; break;
      case '\f': out += "\\f"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        Snprintf(buf, sizeof(buf), "\\u%04x", c);
        out += buf;
        break;
      }
      i++;
      continue;
    }
    if (c < 0x80) {
      out += (char) c;
      i++;
      continue;
    }

    /* Non-ASCII: pass valid UTF-8 through untouched, replace anything else.
       Probe responses and script output are arbitrary bytes, and a JSON
       document has to be valid UTF-8 no matter what came back off the wire. */
    len = utf8_seq_len(c);
    if (len >= 2 && utf8_seq_valid(s, i, len)) {
      out.append(s, i, len);
      i += len;
    } else {
      out += "\\ufffd";
      i++;
    }
  }

  out += '"';

  return out;
}

bool json_is_number(const std::string &s) {
  size_t i = 0;
  bool digits = false;

  if (s.empty())
    return false;

  if (s[i] == '-')
    i++;

  /* int: 0 | [1-9][0-9]* -- no leading zeros, and something must be there. */
  if (i >= s.size())
    return false;
  if (s[i] == '0') {
    i++;
    digits = true;
  } else if (s[i] >= '1' && s[i] <= '9') {
    while (i < s.size() && s[i] >= '0' && s[i] <= '9')
      i++;
    digits = true;
  }
  if (!digits)
    return false;

  /* frac */
  if (i < s.size() && s[i] == '.') {
    i++;
    if (i >= s.size() || s[i] < '0' || s[i] > '9')
      return false;
    while (i < s.size() && s[i] >= '0' && s[i] <= '9')
      i++;
  }

  /* exp */
  if (i < s.size() && (s[i] == 'e' || s[i] == 'E')) {
    i++;
    if (i < s.size() && (s[i] == '+' || s[i] == '-'))
      i++;
    if (i >= s.size() || s[i] < '0' || s[i] > '9')
      return false;
    while (i < s.size() && s[i] >= '0' && s[i] <= '9')
      i++;
  }

  return i == s.size();
}

/*==========================================================================
 * Element tree
 *==========================================================================*/

JsonElement::JsonElement(const char *elname) : name(elname != NULL ? elname : "") {
}

JsonElement::~JsonElement() {
  for (size_t i = 0; i < children.size(); i++)
    delete children[i];
  children.clear();
}

void JsonElement::add_attribute(const char *attrname, const char *value) {
  if (attrname == NULL)
    return;
  attrs.push_back(std::make_pair(std::string(attrname),
                                 std::string(value != NULL ? value : "")));
}

JsonElement *JsonElement::add_child(const char *childname) {
  JsonElement *child = new JsonElement(childname);
  children.push_back(child);
  return child;
}

/*==========================================================================
 * XML -> JSON mapping rules
 *==========================================================================*/

struct element_mapping {
  const char *name; /* XML element name */
  const char *key;  /* key it is stored under in the parent object */
};

/* Elements that may appear more than once, and are therefore always arrays.
   Keeping them arrays even when a single one shows up means consumers never
   have to test whether they got an object or a list. */
static const struct element_mapping ARRAY_ELEMENTS[] = {
  {"address", "addresses"},
  {"cpe", "cpe"},
  {"extraports", "extraports"},
  {"extrareasons", "extrareasons"},
  {"hop", "hops"},
  {"host", "hosts"},
  {"hosthint", "hosthints"},
  {"hostname", "hostnames"},
  {"osclass", "osclasses"},
  {"osfingerprint", "osfingerprints"},
  {"osmatch", "osmatches"},
  {"output", "output"},
  {"port", "ports"},
  {"portused", "portsused"},
  {"scaninfo", "scaninfo"},
  {"script", "scripts"},
  {"target", "targets"},
  {"taskbegin", "taskbegin"},
  {"taskend", "taskend"},
  {"taskprogress", "taskprogress"},
  {NULL, NULL}
};

/* Container elements whose children are lifted into the parent object. The
   second field overrides the key the children are stored under, which is what
   keeps <prescript> and <postscript> results apart. */
static const struct element_mapping TRANSPARENT_ELEMENTS[] = {
  {"hostnames", NULL},
  {"hostscript", NULL},
  {"ports", NULL},
  {"postscript", "postscripts"},
  {"prescript", "prescripts"},
  {NULL, NULL}
};

/* Attributes the DTD declares numeric (%attr_numeric;), plus the handful that
   are declared CDATA but always hold a number. */
static const char *NUMERIC_ATTRIBUTES[] = {
  "accuracy", "conf", "count", "down", "elapsed", "end", "endtime", "etc",
  "highver", "index", "level", "line", "lowver", "numservices", "percent",
  "port", "portid", "reason_ttl", "remaining", "responses", "rpcnum", "rtt",
  "rttvar", "seconds", "srtt", "start", "starttime", "time", "to", "total",
  "ttl", "up", "value", NULL
};

static const char *BOOLEAN_ATTRIBUTES[] = {
  "timedout", NULL
};

static bool in_list(const char *const *list, const std::string &name) {
  for (size_t i = 0; list[i] != NULL; i++) {
    if (name == list[i])
      return true;
  }
  return false;
}

static const struct element_mapping *find_mapping(
    const struct element_mapping *table, const std::string &name) {
  for (size_t i = 0; table[i].name != NULL; i++) {
    if (name == table[i].name)
      return &table[i];
  }
  return NULL;
}

const char *json_key_for_element(const char *name) {
  const struct element_mapping *m;

  if (name == NULL)
    return "";
  m = find_mapping(ARRAY_ELEMENTS, name);
  if (m != NULL)
    return m->key;

  return name;
}

bool json_element_is_array(const char *name) {
  return name != NULL && find_mapping(ARRAY_ELEMENTS, name) != NULL;
}

bool json_element_is_transparent(const char *name) {
  return name != NULL && find_mapping(TRANSPARENT_ELEMENTS, name) != NULL;
}

static const char *transparent_child_key(const std::string &name) {
  const struct element_mapping *m = find_mapping(TRANSPARENT_ELEMENTS, name);
  return m != NULL ? m->key : NULL;
}

/* Turn an attribute into a typed JSON value. */
static JsonValue typed_attribute(const std::string &name, const std::string &value) {
  if (in_list(BOOLEAN_ATTRIBUTES, name)) {
    if (value == "true")
      return JsonValue::make_bool(true);
    if (value == "false")
      return JsonValue::make_bool(false);
    return JsonValue::make_string(value);
  }
  /* Only convert attributes that are meant to be numeric, and only when the
     text really is one: traceroute writes rtt="--" for a hop that timed out,
     and a version string like "7.98" must stay a string. */
  if (in_list(NUMERIC_ATTRIBUTES, name) && json_is_number(value))
    return JsonValue::make_number(value);

  return JsonValue::make_string(value);
}

static const char *attribute_value(const JsonElement *el, const char *name) {
  for (size_t i = 0; i < el->attrs.size(); i++) {
    if (el->attrs[i].first == name)
      return el->attrs[i].second.c_str();
  }
  return NULL;
}

/* Add key => value to an object, promoting to an array if the key is already
   taken.  Nothing an element reported is ever silently dropped. */
static void object_add(JsonValue &obj, const std::string &key, const JsonValue &value) {
  JsonValue *existing = obj.get(key);

  if (existing == NULL) {
    obj.set(key, value);
    return;
  }
  if (existing->is_array()) {
    existing->append(value);
    return;
  }
  {
    JsonValue arr = JsonValue::make_array();
    arr.append(*existing);
    arr.append(value);
    obj.set(key, arr);
  }
}

static JsonValue convert_nse_children(const JsonElement *el);

/* <table> and <elem> are the structured output NSE scripts produce. */
static JsonValue convert_nse_node(const JsonElement *el) {
  if (el->name == "elem")
    return JsonValue::make_string(el->text);
  if (el->name == "table")
    return convert_nse_children(el);

  return json_convert_element(el);
}

static JsonValue convert_nse_children(const JsonElement *el) {
  bool any_keyed = false;
  bool any_unkeyed = false;
  size_t i;

  for (i = 0; i < el->children.size(); i++) {
    if (attribute_value(el->children[i], "key") != NULL)
      any_keyed = true;
    else
      any_unkeyed = true;
  }

  /* A table with no keys is a list; with keys it is a mapping.  A table that
     mixes both keeps the keyed entries as members and collects the rest under
     "_", which is rare but does happen in the wild. */
  if (!any_keyed) {
    JsonValue arr = JsonValue::make_array();
    for (i = 0; i < el->children.size(); i++)
      arr.append(convert_nse_node(el->children[i]));
    return arr;
  }

  {
    JsonValue obj = JsonValue::make_object();
    JsonValue unkeyed = JsonValue::make_array();

    for (i = 0; i < el->children.size(); i++) {
      const JsonElement *child = el->children[i];
      const char *key = attribute_value(child, "key");
      if (key != NULL)
        object_add(obj, key, convert_nse_node(child));
      else
        unkeyed.append(convert_nse_node(child));
    }
    if (any_unkeyed)
      obj.set("_", unkeyed);

    return obj;
  }
}

static JsonValue convert_script(const JsonElement *el) {
  JsonValue obj = JsonValue::make_object();
  size_t i;
  bool has_structured = false;

  for (i = 0; i < el->attrs.size(); i++)
    object_add(obj, el->attrs[i].first, typed_attribute(el->attrs[i].first, el->attrs[i].second));

  for (i = 0; i < el->children.size(); i++) {
    const std::string &cname = el->children[i]->name;
    if (cname == "table" || cname == "elem") {
      has_structured = true;
      break;
    }
  }

  /* The "output" attribute is the human-readable rendering; "data" is the
     same information as a structure, when the script provided one. */
  if (has_structured)
    obj.set("data", convert_nse_children(el));
  else if (!el->text.empty())
    obj.set("data", JsonValue::make_string(el->text));

  return obj;
}

static void add_child_value(JsonValue &parent, const JsonElement *child,
                            const char *key_override) {
  std::string key(key_override != NULL ? key_override : json_key_for_element(child->name.c_str()));
  JsonValue value = json_convert_element(child);
  bool as_array = key_override != NULL || json_element_is_array(child->name.c_str());

  if (!as_array) {
    object_add(parent, key, value);
    return;
  }

  {
    JsonValue *existing = parent.get(key);
    if (existing == NULL) {
      JsonValue arr = JsonValue::make_array();
      arr.append(value);
      parent.set(key, arr);
    } else if (existing->is_array()) {
      existing->append(value);
    } else {
      JsonValue arr = JsonValue::make_array();
      arr.append(*existing);
      arr.append(value);
      parent.set(key, arr);
    }
  }
}

JsonValue json_convert_element(const JsonElement *el) {
  JsonValue obj;
  size_t i;

  if (el == NULL)
    return JsonValue::make_null();

  if (el->name == "script")
    return convert_script(el);
  if (el->name == "table")
    return convert_nse_children(el);
  if (el->name == "elem")
    return JsonValue::make_string(el->text);

  obj = JsonValue::make_object();

  for (i = 0; i < el->attrs.size(); i++)
    object_add(obj, el->attrs[i].first, typed_attribute(el->attrs[i].first, el->attrs[i].second));

  for (i = 0; i < el->children.size(); i++) {
    const JsonElement *child = el->children[i];
    if (json_element_is_transparent(child->name.c_str())) {
      const char *override_key = transparent_child_key(child->name);
      size_t j;
      for (j = 0; j < child->children.size(); j++)
        add_child_value(obj, child->children[j], override_key);
    } else {
      add_child_value(obj, child, NULL);
    }
  }

  if (!el->text.empty()) {
    /* An element that is nothing but text (<cpe>) becomes that text. */
    if (obj.empty())
      return JsonValue::make_string(el->text);
    obj.set("_text", JsonValue::make_string(el->text));
  }

  return obj;
}

/*==========================================================================
 * The streaming writer
 *==========================================================================*/

struct json_writer {
  bool enabled;
  bool lines;           /* newline-delimited JSON instead of one document */
  bool finished;
  bool header_written;  /* root attributes (and pre-host elements) are out */
  bool hosts_open;      /* the "hosts": [ array is still open */
  bool wrote_a_host;
  bool need_comma;      /* a top-level member has already been written */
  JsonElement *root;    /* <nmaprun>, for its attributes */
  JsonElement *subtree; /* the depth-1 element currently being built */
  std::vector<JsonElement *> stack;
  /* Small elements that are not hosts, buffered so that the enclosing object
     can be written in a sensible order. */
  std::vector<std::pair<std::string, JsonValue> > pending;

  json_writer() : enabled(false), lines(false), finished(false),
                  header_written(false), hosts_open(false), wrote_a_host(false),
                  need_comma(false), root(NULL), subtree(NULL) {
  }
};

static struct json_writer jw;

void json_output_enable(bool lines) {
  /* Starting output resets the writer, so enabling twice starts a fresh
     document rather than continuing a half-written one. */
  delete jw.root;
  delete jw.subtree;
  jw = json_writer();
  jw.enabled = true;
  jw.lines = lines;
}

bool json_output_enabled() {
  return jw.enabled;
}

bool json_output_lines_mode() {
  return jw.lines;
}

static void json_emit(const std::string &text) {
  if (text.empty())
    return;
  log_write(LOG_JSON, "%s", text.c_str());
}

/* Write one top-level member of the document object. */
static void write_top_member(const std::string &key, const JsonValue &value) {
  std::string out;

  if (jw.need_comma)
    out += ",\n";
  out += "  ";
  out += json_quote(key);
  out += ": ";
  out += value.dump(2, 1);
  json_emit(out);
  jw.need_comma = true;
}

/* In line mode every record is one object with a "type" discriminator. */
static void write_line_record(const char *type, const JsonValue &value) {
  JsonValue obj = JsonValue::make_object();
  obj.set("type", JsonValue::make_string(type));

  if (value.is_object()) {
    const JsonValue::Members &m = value.members();
    for (size_t i = 0; i < m.size(); i++)
      obj.set(m[i].first, m[i].second);
  } else if (value.type() != JsonValue::JSON_NULL) {
    obj.set("value", value);
  }

  json_emit(obj.dump(-1) + "\n");
}

/* Buffer a non-host top-level element until we know where it belongs. */
static void buffer_pending(const std::string &key, const JsonValue &value, bool as_array) {
  for (size_t i = 0; i < jw.pending.size(); i++) {
    if (jw.pending[i].first != key)
      continue;
    if (jw.pending[i].second.is_array()) {
      jw.pending[i].second.append(value);
    } else {
      JsonValue arr = JsonValue::make_array();
      arr.append(jw.pending[i].second);
      arr.append(value);
      jw.pending[i].second = arr;
    }
    return;
  }

  if (as_array) {
    JsonValue arr = JsonValue::make_array();
    arr.append(value);
    jw.pending.push_back(std::make_pair(key, arr));
  } else {
    jw.pending.push_back(std::make_pair(key, value));
  }
}

/* Write the document header: the root attributes plus everything buffered so
   far except runstats, which belongs at the end.  Called lazily, when the
   first host is ready or when the document is closed, because the elements
   that precede the hosts (scaninfo, verbose, debugging) have to be in hand
   before the object can be written in order. */
static void write_header() {
  size_t i;
  std::vector<std::pair<std::string, JsonValue> > rest;

  if (jw.header_written)
    return;
  jw.header_written = true;

  if (jw.lines) {
    JsonValue obj = JsonValue::make_object();
    obj.set("type", JsonValue::make_string("scan"));
    if (jw.root != NULL) {
      for (i = 0; i < jw.root->attrs.size(); i++) {
        obj.set(jw.root->attrs[i].first,
                typed_attribute(jw.root->attrs[i].first, jw.root->attrs[i].second));
      }
    }
    for (i = 0; i < jw.pending.size(); i++) {
      if (jw.pending[i].first == "runstats")
        rest.push_back(jw.pending[i]);
      else
        obj.set(jw.pending[i].first, jw.pending[i].second);
    }
    jw.pending = rest;
    json_emit(obj.dump(-1) + "\n");
    return;
  }

  json_emit("{\n");
  if (jw.root != NULL) {
    for (i = 0; i < jw.root->attrs.size(); i++) {
      write_top_member(jw.root->attrs[i].first,
                       typed_attribute(jw.root->attrs[i].first, jw.root->attrs[i].second));
    }
  }
  for (i = 0; i < jw.pending.size(); i++) {
    if (jw.pending[i].first == "runstats")
      rest.push_back(jw.pending[i]);
    else
      write_top_member(jw.pending[i].first, jw.pending[i].second);
  }
  jw.pending = rest;
}

static void write_host(const JsonElement *el) {
  JsonValue value = json_convert_element(el);

  write_header();

  if (jw.lines) {
    write_line_record("host", value);
    jw.wrote_a_host = true;
    return;
  }

  if (!jw.hosts_open) {
    std::string out;
    if (jw.need_comma)
      out += ",\n";
    out += "  \"hosts\": [";
    json_emit(out);
    jw.hosts_open = true;
    jw.need_comma = true;
  }

  {
    std::string out;
    out += jw.wrote_a_host ? ",\n" : "\n";
    out += "    ";
    out += value.dump(2, 2);
    json_emit(out);
  }
  jw.wrote_a_host = true;
  /* Complete host records reach the file as they are finished, so a long scan
     can be watched with tail -f. */
  log_flush(LOG_JSON);
}

/* Elements that make up the scan preamble.  They are held back only until the
   preamble is over, so that they can be written as members of the enclosing
   object in the order they appeared. */
static bool is_preamble_element(const std::string &name) {
  return name == "scaninfo" || name == "verbose" || name == "debugging";
}

/* A direct child of <nmaprun> is complete. */
static void flush_subtree(const JsonElement *el) {
  /* Anything past the preamble means the header can go out, which gets the
     start of the document on disk early rather than at the first host. */
  if (!is_preamble_element(el->name))
    write_header();

  if (el->name == "host") {
    write_host(el);
    return;
  }

  if (json_element_is_transparent(el->name.c_str())) {
    const char *override_key = transparent_child_key(el->name);
    for (size_t i = 0; i < el->children.size(); i++) {
      const JsonElement *child = el->children[i];
      const char *key = override_key != NULL ? override_key
                                             : json_key_for_element(child->name.c_str());
      buffer_pending(key, json_convert_element(child), true);
    }
    return;
  }

  buffer_pending(json_key_for_element(el->name.c_str()), json_convert_element(el),
                 json_element_is_array(el->name.c_str()));

  /* The DTD makes <debugging> the last element of the preamble, so once it has
     been buffered the header is complete and can be written.  A scan that is
     killed before its first host still leaves the start of a document behind. */
  if (el->name == "debugging") {
    write_header();
    log_flush(LOG_JSON);
  }
}

void json_mirror_start_element(const char *name) {
  if (!jw.enabled || jw.finished)
    return;

  if (jw.stack.empty()) {
    /* <nmaprun>. Only its attributes matter; children are streamed. */
    if (jw.root == NULL)
      jw.root = new JsonElement(name);
    jw.stack.push_back(jw.root);
    return;
  }

  if (jw.stack.size() == 1) {
    jw.subtree = new JsonElement(name);
    jw.stack.push_back(jw.subtree);
    return;
  }

  jw.stack.push_back(jw.stack.back()->add_child(name));
}

void json_mirror_attribute(const char *name, const char *value) {
  if (!jw.enabled || jw.finished || jw.stack.empty())
    return;
  jw.stack.back()->add_attribute(name, value);
}

void json_mirror_characters(const char *text) {
  if (!jw.enabled || jw.finished || jw.stack.size() < 2 || text == NULL)
    return;
  jw.stack.back()->text += text;
}

void json_mirror_end_element() {
  if (!jw.enabled || jw.finished || jw.stack.empty())
    return;

  jw.stack.pop_back();

  if (jw.stack.empty()) {
    /* </nmaprun> */
    json_output_finish();
    return;
  }

  if (jw.stack.size() == 1 && jw.subtree != NULL) {
    flush_subtree(jw.subtree);
    delete jw.subtree;
    jw.subtree = NULL;
  }
}

void json_output_finish() {
  size_t i;

  if (!jw.enabled || jw.finished)
    return;
  /* Only the mirror entry points test this flag, so the writers below still
     run. It is set first so that a fatal error raised while finishing cannot
     send us round again. */
  jw.finished = true;

  /* An interrupted scan can leave elements open. Their partial data is still
     worth writing out, so close them instead of dropping the subtree. */
  while (jw.stack.size() > 1) {
    jw.stack.pop_back();
    if (jw.stack.size() == 1 && jw.subtree != NULL) {
      flush_subtree(jw.subtree);
      delete jw.subtree;
      jw.subtree = NULL;
    }
  }
  jw.stack.clear();

  write_header();

  if (jw.lines) {
    for (i = 0; i < jw.pending.size(); i++) {
      const std::string &key = jw.pending[i].first;
      const JsonValue &value = jw.pending[i].second;
      if (value.is_array()) {
        /* One record per item keeps every line self-contained. */
        for (size_t j = 0; j < value.size(); j++)
          write_line_record(key.c_str(), *value.at(j));
      } else {
        write_line_record(key.c_str(), value);
      }
    }
    jw.pending.clear();
    log_flush(LOG_JSON);
    delete jw.root;
    jw.root = NULL;
    return;
  }

  if (jw.hosts_open) {
    json_emit("\n  ]");
    jw.hosts_open = false;
  } else {
    /* Always present, so that consumers can iterate it unconditionally. */
    write_top_member("hosts", JsonValue::make_array());
  }

  for (i = 0; i < jw.pending.size(); i++)
    write_top_member(jw.pending[i].first, jw.pending[i].second);
  jw.pending.clear();

  json_emit("\n}\n");
  log_flush(LOG_JSON);

  delete jw.root;
  jw.root = NULL;
}

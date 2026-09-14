/***************************************************************************
 * json.h -- Streaming JSON output for Nmap.  This is the interface to the  *
 * JSON document writer that mirrors Nmap's XML output tree, plus the       *
 * minimal JSON value model it is built on.                                 *
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

#ifndef NMAP_JSON_H
#define NMAP_JSON_H

#include <stddef.h>

#include <string>
#include <utility>
#include <vector>

/*
 * JSON output is produced by mirroring the calls that build the XML document.
 * Every piece of information Nmap knows how to report already passes through
 * xml.cc, so hooking that one funnel means the JSON document carries exactly
 * the same data as the XML one, without a second set of call sites that can
 * drift out of sync.
 *
 * The writer is streaming: host objects are serialized and written as soon as
 * their </host> arrives, so memory use is bounded by the largest single host
 * rather than by the size of the scan.  Everything else in the document (the
 * root attributes, scaninfo, verbose/debugging, task events and runstats) is
 * small and is buffered so that the surrounding object can be written in a
 * sensible order.
 */

/*--------------------------------------------------------------------------
 * A minimal JSON value model.
 *
 * Objects preserve insertion order, which keeps the output diffable and
 * readable.  Numbers are stored as their literal text so that Nmap's own
 * formatting ("0.02", "1789428546") survives a round trip without being
 * mangled by a float conversion.
 *--------------------------------------------------------------------------*/
class JsonValue {
public:
  enum Type {
    JSON_NULL,
    JSON_BOOL,
    JSON_NUMBER,
    JSON_STRING,
    JSON_ARRAY,
    JSON_OBJECT
  };

  typedef std::vector<std::pair<std::string, JsonValue> > Members;

  JsonValue();

  static JsonValue make_null();
  static JsonValue make_bool(bool value);
  /* literal must already be a valid JSON number, see json_is_number(). */
  static JsonValue make_number(const std::string &literal);
  static JsonValue make_string(const std::string &value);
  static JsonValue make_array();
  static JsonValue make_object();

  Type type() const { return t; }
  bool is_object() const { return t == JSON_OBJECT; }
  bool is_array() const { return t == JSON_ARRAY; }

  /* Object operations. set() replaces an existing key in place, keeping its
     original position. */
  void set(const std::string &key, const JsonValue &value);
  JsonValue *get(const std::string &key);
  const JsonValue *get(const std::string &key) const;
  const Members &members() const { return obj; }

  /* Array operations. */
  void append(const JsonValue &value);
  const JsonValue *at(size_t index) const;
  size_t size() const;
  bool empty() const;

  /* Serialize this value.  indent < 0 produces compact single-line output;
     otherwise each nesting level is indented by that many spaces.  The first
     line is not indented: the caller decides where the value starts.  level
     is the nesting level the value is being written at. */
  std::string dump(int indent = 2, int level = 0) const;

private:
  Type t;
  bool b;
  std::string s; /* string contents, or the literal text of a number */
  std::vector<JsonValue> arr;
  Members obj;
};

/* Quote and escape a string as a JSON string literal, surrounding quotes
   included.  Bytes that are not valid UTF-8 are emitted as � so that the
   result is always a well-formed JSON string, whatever a probe response
   contained. */
std::string json_quote(const std::string &s);

/* True if the text is a valid JSON number literal (RFC 8259), which is
   stricter than strtod: no leading '+', no leading zeros, no "0x", no "inf",
   no trailing garbage. */
bool json_is_number(const std::string &s);

/*--------------------------------------------------------------------------
 * The captured XML element tree.
 *
 * This is exposed so the conversion rules can be unit tested (see
 * tests/json_output_test.cc) without running a scan.
 *--------------------------------------------------------------------------*/
struct JsonElement {
  std::string name;
  std::vector<std::pair<std::string, std::string> > attrs;
  std::string text;
  std::vector<JsonElement *> children;

  explicit JsonElement(const char *elname);
  ~JsonElement();

  void add_attribute(const char *attrname, const char *value);
  JsonElement *add_child(const char *childname);

private:
  /* Owns its children; copying would double-free. */
  JsonElement(const JsonElement &);
  JsonElement &operator=(const JsonElement &);
};

/* The JSON key an element is stored under inside its parent object.  Most
   repeated elements get a plural key ("host" -> "hosts") so that the result
   reads naturally in jq. */
const char *json_key_for_element(const char *name);

/* True if the element always becomes a JSON array, even when it appears only
   once.  A single open port must still be hosts[0].ports[0]. */
bool json_element_is_array(const char *name);

/* True if the element is a pure container whose children are lifted into the
   parent object (<hostnames>, <ports>, <hostscript>, ...). */
bool json_element_is_transparent(const char *name);

/* Convert one element subtree into its JSON representation. */
JsonValue json_convert_element(const JsonElement *el);

/*--------------------------------------------------------------------------
 * The writer, driven from xml.cc.
 *--------------------------------------------------------------------------*/

/* Turn JSON output on.  When lines is true the writer emits newline-delimited
   JSON (one object per line) instead of a single document. */
void json_output_enable(bool lines);
bool json_output_enabled();
bool json_output_lines_mode();

/* Mirror hooks.  These are no-ops unless JSON output is enabled. */
void json_mirror_start_element(const char *name);
void json_mirror_attribute(const char *name, const char *value);
void json_mirror_characters(const char *text);
void json_mirror_end_element();

/* Flush whatever is still buffered and close the document.  Idempotent, and
   safe to call on an incomplete document: an interrupted scan still yields
   parseable JSON. */
void json_output_finish();

#endif /* NMAP_JSON_H */

---
-- Parsing and summarizing of OpenAPI (formerly Swagger) description documents.
--
-- An OpenAPI document describes every path, operation, parameter and security
-- scheme a web API accepts. Services publish it so that clients and code
-- generators can consume it, and it is frequently reachable without
-- authentication, which makes it a complete map of the API's attack surface.
--
-- This module knows how to recognize such a document, whether it is JSON or
-- YAML, and how to reduce it to the handful of facts worth reporting. It has
-- no network code; <code>http-openapi-discover.nse</code> fetches the
-- documents and this module makes sense of them.
--
-- @author Nmap contributors
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html

local json = require "json"
local math = require "math"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local unittest = require "unittest"

local ipairs = ipairs
local pairs = pairs
local tonumber = tonumber
local tostring = tostring
local type = type

_ENV = stdnse.module("openapi", stdnse.seeall)

--- Locations that publish a description document.
--
-- Covers the defaults of FastAPI, Flask extensions, Django REST framework,
-- Springdoc and Springfox, Quarkus, ASP.NET Core (Swashbuckle), NestJS and the
-- common API gateways, plus the conventional hand-written locations.
DEFAULT_PATHS = {
  "/openapi.json",
  "/openapi.yaml",
  "/swagger.json",
  "/swagger.yaml",
  "/swagger/v1/swagger.json",
  "/v2/api-docs",
  "/v3/api-docs",
  "/api-docs",
  "/api/openapi.json",
  "/api/swagger.json",
  "/api/v1/openapi.json",
  "/api/docs/openapi.json",
  "/docs/openapi.json",
  "/q/openapi",
  "/.well-known/openapi.json",
}

local HTTP_METHODS = {
  get = true, put = true, post = true, delete = true,
  options = true, head = true, patch = true, trace = true,
}

--- Returns the specification version a parsed document declares.
--
-- @param doc A table, as returned by <code>json.parse</code>.
-- @return A string such as "OpenAPI 3.0.3" or "Swagger 2.0", or nil if the
--         table is not a description document.
function spec_version(doc)
  if type(doc) ~= "table" then
    return nil
  end
  if type(doc.openapi) == "string" then
    return "OpenAPI " .. doc.openapi
  end
  if type(doc.swagger) == "string" then
    return "Swagger " .. doc.swagger
  end
  return nil
end

--- True if the table looks like an OpenAPI or Swagger document.
function is_document(doc)
  return spec_version(doc) ~= nil
end

--- Extracts what can be had from a YAML document without a YAML parser.
--
-- Only the scalars this module reports are looked for, which keeps this to
-- simple pattern matching. A document that cannot be recognized returns nil,
-- so a false positive needs a line that literally starts with "openapi:" or
-- "swagger:" followed by a version number.
--
-- @param body The document text.
-- @return A table with <code>spec</code>, and possibly <code>title</code> and
--         <code>api_version</code>, or nil.
function parse_yamlish(body)
  if type(body) ~= "string" then
    return nil
  end

  local info = {}
  local version = body:match("^%s*openapi%s*:%s*[\"']?([%d][%d%.]*)")
      or body:match("\n%s*openapi%s*:%s*[\"']?([%d][%d%.]*)")
  if version then
    info.spec = "OpenAPI " .. version
  else
    version = body:match("^%s*swagger%s*:%s*[\"']?([%d][%d%.]*)")
        or body:match("\n%s*swagger%s*:%s*[\"']?([%d][%d%.]*)")
    if not version then
      return nil
    end
    info.spec = "Swagger " .. version
  end

  local title = body:match("\n%s*title%s*:%s*[\"']?([^\"'\r\n]+)")
  local api_version = body:match("\n%s*version%s*:%s*[\"']?([^\"'\r\n]+)")
  if title then
    info.title = (title:gsub("%s+$", ""))
  end
  if api_version then
    info.api_version = (api_version:gsub("%s+$", ""))
  end

  return info
end

--- Parses a description document.
--
-- JSON is tried first; if that fails the body is treated as YAML and the few
-- fields that can be recovered with pattern matching are returned instead. A
-- body that is neither returns nil.
--
-- @param body The document text.
-- @return doc The parsed JSON document, or nil if it was not JSON.
-- @return info A table of recovered YAML fields, or nil.
function parse(body)
  if type(body) ~= "string" or body == "" then
    return nil, nil
  end

  local ok, doc = json.parse(body)
  if ok and is_document(doc) then
    return doc, nil
  end

  return nil, parse_yamlish(body)
end

--- Lists the operations a document declares, as "METHOD /path" strings.
--
-- The result is sorted, so output does not depend on table iteration order.
function operations(doc)
  local result = {}

  if type(doc) ~= "table" or type(doc.paths) ~= "table" then
    return result
  end

  for path, item in pairs(doc.paths) do
    if type(path) == "string" and type(item) == "table" then
      for method in pairs(item) do
        if type(method) == "string" and HTTP_METHODS[method:lower()] then
          result[#result + 1] = method:upper() .. " " .. path
        end
      end
    end
  end
  table.sort(result)

  return result
end

--- Counts the paths a document declares.
function path_count(doc)
  local count = 0

  if type(doc) ~= "table" or type(doc.paths) ~= "table" then
    return 0
  end
  for path in pairs(doc.paths) do
    if type(path) == "string" then
      count = count + 1
    end
  end

  return count
end

--- Lists the servers a document declares.
--
-- OpenAPI 3 states them as URLs; Swagger 2 spells them out in host, basePath
-- and schemes, which are put back together here.
function servers(doc)
  local result = {}

  if type(doc) ~= "table" then
    return result
  end

  if type(doc.servers) == "table" then
    for _, server in ipairs(doc.servers) do
      if type(server) == "table" and type(server.url) == "string" then
        result[#result + 1] = server.url
      end
    end
  elseif type(doc.host) == "string" then
    local scheme = "http"
    if type(doc.schemes) == "table" and doc.schemes[1] ~= nil then
      scheme = tostring(doc.schemes[1])
    end
    result[#result + 1] = scheme .. "://" .. doc.host .. (doc.basePath or "")
  end

  return result
end

--- Lists the security schemes a document declares, as "name (type)".
function security_schemes(doc)
  local result = {}
  local definitions

  if type(doc) ~= "table" then
    return result
  end
  if type(doc.components) == "table" and type(doc.components.securitySchemes) == "table" then
    definitions = doc.components.securitySchemes
  elseif type(doc.securityDefinitions) == "table" then
    definitions = doc.securityDefinitions
  else
    return result
  end

  local names = {}
  for name in pairs(definitions) do
    if type(name) == "string" then
      names[#names + 1] = name
    end
  end
  table.sort(names)

  for _, name in ipairs(names) do
    local scheme = definitions[name]
    if type(scheme) == "table" and type(scheme.type) == "string" then
      result[#result + 1] = string.format("%s (%s)", name, scheme.type)
    else
      result[#result + 1] = name
    end
  end

  return result
end

--- Reduces a document to the facts worth reporting.
--
-- @param doc A parsed document.
-- @param options A table which may contain <code>showpaths</code> (list the
--        operations) and <code>maxpaths</code> (how many to list, default 50).
-- @return An ordered table suitable for returning from a script action, or nil
--         if doc is not a description document.
function describe(doc, options)
  options = options or {}

  local spec = spec_version(doc)
  if not spec then
    return nil
  end

  local out = stdnse.output_table()
  out.spec = spec

  if type(doc.info) == "table" then
    if type(doc.info.title) == "string" then
      out.title = doc.info.title
    end
    if type(doc.info.version) == "string" then
      out.api_version = doc.info.version
    end
    if type(doc.info.description) == "string" then
      local description = doc.info.description:gsub("%s+", " ")
      if #description > 120 then
        description = description:sub(1, 117) .. "..."
      end
      out.description = description
    end
  end

  local ops = operations(doc)
  out.paths = path_count(doc)
  out.operations = #ops

  local srv = servers(doc)
  if #srv > 0 then
    out.servers = srv
  end

  local schemes = security_schemes(doc)
  if #schemes > 0 then
    out.security_schemes = schemes
  end

  if options.showpaths and #ops > 0 then
    local limit = tonumber(options.maxpaths) or 50
    local listed = {}
    for i = 1, math.min(#ops, limit) do
      listed[i] = ops[i]
    end
    if #ops > limit then
      listed[#listed + 1] = string.format("... and %d more", #ops - limit)
    end
    out.endpoints = listed
  end

  return out
end

test_suite = unittest.TestSuite:new()

do
  local openapi3 = [[{
    "openapi": "3.0.3",
    "info": {"title": "Payments API", "version": "2.4.1",
             "description": "Internal   payments\nservice"},
    "servers": [{"url": "https://api.example.com/v2"}],
    "paths": {
      "/users": {"get": {}, "post": {}},
      "/users/{id}": {"get": {}, "delete": {}, "parameters": []}
    },
    "components": {"securitySchemes": {
      "bearerAuth": {"type": "http", "scheme": "bearer"},
      "apiKey": {"type": "apiKey", "in": "header", "name": "X-Key"}
    }}
  }]]

  local swagger2 = [[{
    "swagger": "2.0",
    "info": {"title": "Legacy API", "version": "1.0"},
    "host": "legacy.example.com",
    "basePath": "/api",
    "schemes": ["https"],
    "paths": {"/ping": {"get": {}}},
    "securityDefinitions": {"basicAuth": {"type": "basic"}}
  }]]

  local doc3 = parse(openapi3)
  local doc2 = parse(swagger2)

  test_suite:add_test(unittest.not_nil(doc3), "OpenAPI 3 document parses")
  test_suite:add_test(unittest.not_nil(doc2), "Swagger 2 document parses")
  test_suite:add_test(unittest.equal(spec_version(doc3), "OpenAPI 3.0.3"), "OpenAPI 3 version")
  test_suite:add_test(unittest.equal(spec_version(doc2), "Swagger 2.0"), "Swagger 2 version")
  test_suite:add_test(unittest.is_true(is_document(doc3)), "is_document accepts a document")
  test_suite:add_test(unittest.is_false(is_document({hello = "world"})),
    "is_document rejects unrelated JSON")
  test_suite:add_test(unittest.is_false(is_document("not a table")),
    "is_document rejects a string")

  test_suite:add_test(unittest.equal(path_count(doc3), 2), "path count")
  test_suite:add_test(unittest.equal(#operations(doc3), 4), "operation count")
  -- "parameters" sits beside the methods in a path item and is not one.
  test_suite:add_test(unittest.equal(operations(doc3)[1], "DELETE /users/{id}"),
    "operations are sorted and exclude non-methods")
  test_suite:add_test(unittest.equal(#operations({}), 0), "operations of an empty document")

  test_suite:add_test(unittest.equal(servers(doc3)[1], "https://api.example.com/v2"),
    "OpenAPI 3 server URL")
  test_suite:add_test(unittest.equal(servers(doc2)[1], "https://legacy.example.com/api"),
    "Swagger 2 server URL is reassembled")

  test_suite:add_test(unittest.equal(security_schemes(doc3)[1], "apiKey (apiKey)"),
    "security schemes are sorted")
  test_suite:add_test(unittest.equal(security_schemes(doc3)[2], "bearerAuth (http)"),
    "security scheme type")
  test_suite:add_test(unittest.equal(security_schemes(doc2)[1], "basicAuth (basic)"),
    "Swagger 2 security definitions")

  local described = describe(doc3, {showpaths = true, maxpaths = 2})
  test_suite:add_test(unittest.equal(described.title, "Payments API"), "described title")
  test_suite:add_test(unittest.equal(described.api_version, "2.4.1"), "described version")
  test_suite:add_test(unittest.equal(described.paths, 2), "described path count")
  test_suite:add_test(unittest.equal(described.operations, 4), "described operation count")
  test_suite:add_test(unittest.equal(described.description, "Internal payments service"),
    "description whitespace is collapsed")
  test_suite:add_test(unittest.equal(#described.endpoints, 3),
    "endpoint list is capped and notes the remainder")
  test_suite:add_test(unittest.equal(described.endpoints[3], "... and 2 more"),
    "endpoint list remainder")
  test_suite:add_test(unittest.is_nil(describe({not_a = "document"})),
    "describe rejects unrelated JSON")

  local yaml = "openapi: 3.1.0\ninfo:\n  title: YAML API\n  version: 9.9\npaths: {}\n"
  local doc_from_yaml, info = parse(yaml)
  test_suite:add_test(unittest.is_nil(doc_from_yaml), "YAML is not parsed as JSON")
  test_suite:add_test(unittest.equal(info.spec, "OpenAPI 3.1.0"), "YAML spec version")
  test_suite:add_test(unittest.equal(info.title, "YAML API"), "YAML title")
  test_suite:add_test(unittest.equal(info.api_version, "9.9"), "YAML api version")

  test_suite:add_test(unittest.is_nil(parse_yamlish("hello: world\n")),
    "unrelated YAML is not a document")
  test_suite:add_test(unittest.is_nil(parse_yamlish("")), "empty body is not a document")
  test_suite:add_test(unittest.is_nil((parse(""))), "parse of an empty body")
  test_suite:add_test(unittest.is_nil((parse("<html></html>"))), "parse of an HTML body")
end

return _ENV

---
-- Recognition of GraphQL endpoints and of the schema they disclose.
--
-- A GraphQL service answers every operation at a single path, which makes it
-- invisible to the path-based discovery that works for REST APIs. It also
-- offers introspection: a query that returns the service's entire type system,
-- every field and every mutation. Introspection is meant for development tools
-- and is supposed to be turned off in production, where leaving it on hands
-- over a complete description of the API.
--
-- This module builds the queries and interprets the answers. It has no network
-- code; <code>http-graphql-introspection.nse</code> does the requests and this
-- module decides what they mean.
--
-- @author Nmap contributors
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html

local json = require "json"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local unittest = require "unittest"

local ipairs = ipairs
local pairs = pairs
local type = type

_ENV = stdnse.module("graphql", stdnse.seeall)

--- Paths that commonly serve a GraphQL endpoint.
DEFAULT_PATHS = {
  "/graphql",
  "/api/graphql",
  "/v1/graphql",
  "/graphql/v1",
  "/query",
  "/gql",
  "/api/v1/graphql",
  "/graphql/api",
}

--- The smallest valid query there is: every schema has __typename.
TYPENAME_QUERY = "{__typename}"

--- Asks for the shape of the schema without pulling every field description.
--
-- Deliberately smaller than the introspection query a client tool would send:
-- it is enough to say whether introspection is on and what the API exposes,
-- without asking the server to serialize its entire documentation.
INTROSPECTION_QUERY = "query{__schema{queryType{name fields{name}}"
    .. "mutationType{name}subscriptionType{name}types{name kind}}}"

--- Encodes a query as a GraphQL-over-HTTP request body.
function build_request(query)
  return json.generate({query = query})
end

local GRAPHQL_ERROR_PATTERNS = {
  "cannot query field",
  "syntax error",
  "graphql",
  "must be defined",
  "unknown operation",
  "query root type",
  "operation name",
  "no query string",
  "must provide query string",
}

local function looks_like_graphql_error(errors)
  if type(errors) ~= "table" then
    return false
  end

  for _, err in ipairs(errors) do
    if type(err) == "table" then
      -- locations and extensions are part of the GraphQL error shape and are
      -- rare elsewhere.
      if type(err.locations) == "table" or type(err.extensions) == "table" then
        return true
      end
      if type(err.message) == "string" then
        local message = err.message:lower()
        for _, pattern in ipairs(GRAPHQL_ERROR_PATTERNS) do
          if message:find(pattern, 1, true) then
            return true
          end
        end
      end
    end
  end

  return false
end

--- Decides whether a response body came from a GraphQL endpoint.
--
-- @param body The response body.
-- @return "confirmed" when the body answers a __typename query, "likely" when
--         it is a GraphQL-shaped error, or nil when it is neither.
-- @return The __typename value, when there is one.
function classify(body)
  if type(body) ~= "string" or body == "" then
    return nil
  end

  local ok, doc = json.parse(body)
  if not ok or type(doc) ~= "table" then
    return nil
  end

  if type(doc.data) == "table" and type(doc.data.__typename) == "string" then
    return "confirmed", doc.data.__typename
  end

  -- An endpoint that rejects the query with a GraphQL error is still a
  -- GraphQL endpoint, and that is how servers behave when a query is sent
  -- with the wrong content type or when only POST is allowed.
  if looks_like_graphql_error(doc.errors) then
    return "likely"
  end

  return nil
end

--- Extracts the first error message from a GraphQL response.
function first_error(body)
  if type(body) ~= "string" then
    return nil
  end

  local ok, doc = json.parse(body)
  if not ok or type(doc) ~= "table" or type(doc.errors) ~= "table" then
    return nil
  end

  for _, err in ipairs(doc.errors) do
    if type(err) == "table" and type(err.message) == "string" then
      local message = err.message:gsub("%s+", " ")
      if #message > 160 then
        message = message:sub(1, 157) .. "..."
      end
      return message
    end
  end

  return nil
end

--- Summarizes the answer to an introspection query.
--
-- @param body The response body.
-- @param options A table which may contain <code>maxfields</code>, the number
--        of query field names to list. Default: 15.
-- @return An ordered table describing the schema, or nil if the body is not a
--         successful introspection response.
function summarize(body, options)
  options = options or {}

  if type(body) ~= "string" or body == "" then
    return nil
  end

  local ok, doc = json.parse(body)
  if not ok or type(doc) ~= "table" then
    return nil
  end
  if type(doc.data) ~= "table" or type(doc.data.__schema) ~= "table" then
    return nil
  end

  local schema = doc.data.__schema
  local out = stdnse.output_table()

  if type(schema.queryType) == "table" and type(schema.queryType.name) == "string" then
    out.query_type = schema.queryType.name
  end
  if type(schema.mutationType) == "table" and type(schema.mutationType.name) == "string" then
    out.mutation_type = schema.mutationType.name
  end
  if type(schema.subscriptionType) == "table" and type(schema.subscriptionType.name) == "string" then
    out.subscription_type = schema.subscriptionType.name
  end

  -- Types whose names start with "__" belong to the introspection system
  -- itself and say nothing about this particular API.
  local custom_types = 0
  local object_types = {}
  if type(schema.types) == "table" then
    for _, entry in ipairs(schema.types) do
      if type(entry) == "table" and type(entry.name) == "string"
          and entry.name:sub(1, 2) ~= "__" then
        custom_types = custom_types + 1
        if entry.kind == "OBJECT" then
          object_types[#object_types + 1] = entry.name
        end
      end
    end
  end
  out.types = custom_types
  if #object_types > 0 then
    out.object_types = #object_types
  end

  local fields = {}
  if type(schema.queryType) == "table" and type(schema.queryType.fields) == "table" then
    for _, field in ipairs(schema.queryType.fields) do
      if type(field) == "table" and type(field.name) == "string" then
        fields[#fields + 1] = field.name
      end
    end
    table.sort(fields)
  end
  if #fields > 0 then
    local limit = options.maxfields or 15
    out.query_fields = #fields
    local listed = {}
    for i = 1, (#fields < limit and #fields or limit) do
      listed[i] = fields[i]
    end
    if #fields > limit then
      listed[#listed + 1] = string.format("... and %d more", #fields - limit)
    end
    out.query_field_names = listed
  end

  return out
end

test_suite = unittest.TestSuite:new()

do
  local typename_ok = '{"data":{"__typename":"Query"}}'
  local typename_root = '{"data":{"__typename":"RootQueryType"}}'
  local graphql_error = '{"errors":[{"message":"Syntax Error: Unexpected <EOF>.",'
      .. '"locations":[{"line":1,"column":1}]}]}'
  local apollo_error = '{"errors":[{"message":"GET query missing.",'
      .. '"extensions":{"code":"BAD_REQUEST"}}]}'
  local rest_error = '{"errors":[{"message":"invalid id"}]}'
  local rest_ok = '{"data":{"id":7,"name":"thing"}}'

  local status, typename = classify(typename_ok)
  test_suite:add_test(unittest.equal(status, "confirmed"), "__typename answer is confirmed")
  test_suite:add_test(unittest.equal(typename, "Query"), "__typename value")
  test_suite:add_test(unittest.equal((classify(typename_root)), "confirmed"),
    "non-standard root type name")
  test_suite:add_test(unittest.equal((classify(graphql_error)), "likely"),
    "error with locations is likely GraphQL")
  test_suite:add_test(unittest.equal((classify(apollo_error)), "likely"),
    "error with extensions is likely GraphQL")
  test_suite:add_test(unittest.is_nil((classify(rest_error))),
    "a plain errors array is not enough")
  test_suite:add_test(unittest.is_nil((classify(rest_ok))), "a REST answer is not GraphQL")
  test_suite:add_test(unittest.is_nil((classify("<html></html>"))), "HTML is not GraphQL")
  test_suite:add_test(unittest.is_nil((classify(""))), "empty body")
  test_suite:add_test(unittest.is_nil((classify(nil))), "nil body")

  test_suite:add_test(unittest.equal(first_error(graphql_error),
    "Syntax Error: Unexpected <EOF>."), "first error message")
  test_suite:add_test(unittest.is_nil(first_error(typename_ok)), "no error to report")

  local introspection = [[{"data":{"__schema":{
    "queryType":{"name":"Query","fields":[{"name":"users"},{"name":"me"},{"name":"orders"}]},
    "mutationType":{"name":"Mutation"},
    "subscriptionType":null,
    "types":[{"name":"Query","kind":"OBJECT"},{"name":"User","kind":"OBJECT"},
             {"name":"Role","kind":"ENUM"},{"name":"__Schema","kind":"OBJECT"},
             {"name":"__Type","kind":"OBJECT"}]}}}]]

  local summary = summarize(introspection)
  test_suite:add_test(unittest.not_nil(summary), "introspection response is summarized")
  test_suite:add_test(unittest.equal(summary.query_type, "Query"), "query type name")
  test_suite:add_test(unittest.equal(summary.mutation_type, "Mutation"), "mutation type name")
  test_suite:add_test(unittest.is_nil(summary.subscription_type),
    "a null subscription type is left out")
  test_suite:add_test(unittest.equal(summary.types, 3),
    "introspection types are not counted as the API's own")
  test_suite:add_test(unittest.equal(summary.object_types, 2), "object type count")
  test_suite:add_test(unittest.equal(summary.query_fields, 3), "query field count")
  test_suite:add_test(unittest.equal(summary.query_field_names[1], "me"),
    "query fields are sorted")

  local capped = summarize(introspection, {maxfields = 2})
  test_suite:add_test(unittest.equal(#capped.query_field_names, 3),
    "field list is capped and notes the remainder")
  test_suite:add_test(unittest.equal(capped.query_field_names[3], "... and 1 more"),
    "field list remainder")

  test_suite:add_test(unittest.is_nil(summarize(typename_ok)),
    "a __typename answer is not an introspection result")
  test_suite:add_test(unittest.is_nil(summarize(graphql_error)),
    "an error is not an introspection result")
  test_suite:add_test(unittest.is_nil(summarize("")), "empty introspection body")

  test_suite:add_test(unittest.equal(build_request("{__typename}"),
    '{"query": "{__typename}"}'), "request body")
end

return _ENV

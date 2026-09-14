local graphql = require "graphql"
local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local stringaux = require "stringaux"

description = [[
Finds GraphQL endpoints and reports whether they allow introspection.

A GraphQL service answers every operation at one path, so it does not show up
in the path-based discovery that finds REST APIs. This script looks for the
usual locations, confirms them with the smallest valid query there is
(<code>{__typename}</code>), and then asks whether introspection is enabled.

Introspection returns the service's entire type system: every type, every query
and every mutation, including the ones that were never meant to be public. It
exists for development tools and is supposed to be disabled in production, so
an endpoint that answers an introspection query is disclosing a complete
description of its API to anyone who asks. When it is enabled the script
reports the root type names, how many types the schema defines and the fields
of the query root.

The script sends two POST requests per candidate path, both of them read-only
queries against the schema; it never calls an operation the schema describes.
]]

---
-- @usage nmap -p 80,443 --script http-graphql-introspection <target>
-- @usage nmap -p 8080 --script http-graphql-introspection --script-args http-graphql-introspection.path=/api/graphql <target>
--
-- @args http-graphql-introspection.path A single path to check instead of the
--       built-in list.
-- @args http-graphql-introspection.paths A comma-separated list of paths to
--       check instead of the built-in list.
-- @args http-graphql-introspection.maxfields Maximum number of query field
--       names to list. Default: 15.
-- @args http-graphql-introspection.all If set, keep looking after the first
--       endpoint is found instead of stopping at it.
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | http-graphql-introspection:
-- |   /graphql:
-- |     detection: confirmed (__typename = Query)
-- |     introspection: enabled
-- |     query_type: Query
-- |     mutation_type: Mutation
-- |     types: 42
-- |     object_types: 18
-- |     query_fields: 3
-- |     query_field_names:
-- |       me
-- |       orders
-- |       users
-- |_    note: introspection discloses the complete schema to unauthenticated clients
--
-- @xmloutput
-- <table key="/graphql">
--   <elem key="detection">confirmed (__typename = Query)</elem>
--   <elem key="introspection">enabled</elem>
--   <elem key="query_type">Query</elem>
--   <elem key="mutation_type">Mutation</elem>
--   <elem key="types">42</elem>
--   <elem key="object_types">18</elem>
--   <elem key="query_fields">3</elem>
--   <table key="query_field_names">
--     <elem>me</elem>
--     <elem>orders</elem>
--     <elem>users</elem>
--   </table>
--   <elem key="note">introspection discloses the complete schema to unauthenticated clients</elem>
-- </table>

author = "Nmap contributors"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"discovery", "safe"}

portrule = shortport.http

local function candidate_paths()
  local single = stdnse.get_script_args(SCRIPT_NAME .. ".path")
  if single then
    return {single}
  end

  local list = stdnse.get_script_args(SCRIPT_NAME .. ".paths")
  if list then
    local paths = {}
    for _, path in ipairs(stringaux.strsplit(",", list)) do
      path = path:gsub("^%s+", ""):gsub("%s+$", "")
      if path ~= "" then
        paths[#paths + 1] = path
      end
    end
    if #paths > 0 then
      return paths
    end
  end

  return graphql.DEFAULT_PATHS
end

local function post_query(host, port, path, query)
  return http.post(host, port, path, {
    header = {
      ["Content-Type"] = "application/json",
      ["Accept"] = "application/json",
    },
    redirect_ok = false,
    no_cache = true,
  }, nil, graphql.build_request(query))
end

action = function(host, port)
  local paths = candidate_paths()
  local find_all = stdnse.get_script_args(SCRIPT_NAME .. ".all") ~= nil
  local maxfields = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".maxfields")) or 15

  local output = stdnse.output_table()
  local found = 0

  for _, path in ipairs(paths) do
    local response = post_query(host, port, path, graphql.TYPENAME_QUERY)

    if response and response.body then
      local status, typename = graphql.classify(response.body)

      if status then
        local entry = stdnse.output_table()
        if status == "confirmed" then
          entry.detection = string.format("confirmed (__typename = %s)", typename)
        else
          entry.detection = "likely (GraphQL-shaped error)"
        end

        local introspection = post_query(host, port, path, graphql.INTROSPECTION_QUERY)
        local summary = introspection and introspection.body
            and graphql.summarize(introspection.body, {maxfields = maxfields})

        if summary then
          entry.introspection = "enabled"
          for key, value in pairs(summary) do
            entry[key] = value
          end
          entry.note = "introspection discloses the complete schema to "
              .. "unauthenticated clients"
        else
          entry.introspection = "disabled"
          local reason = introspection and introspection.body
              and graphql.first_error(introspection.body)
          if reason then
            entry.reason = reason
          end
        end

        found = found + 1
        output[path] = entry
        if not find_all then
          break
        end
      end
    end
  end

  if found == 0 then
    return nil
  end

  return output
end

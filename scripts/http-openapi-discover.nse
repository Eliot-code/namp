local http = require "http"
local openapi = require "openapi"
local shortport = require "shortport"
local stdnse = require "stdnse"
local stringaux = require "stringaux"

description = [[
Looks for an exposed OpenAPI (Swagger) description document and reports what it
says about the API.

Machine-readable API descriptions are published by most modern frameworks, and
are frequently reachable without authentication even when the API itself is
not. Such a document is a map of the whole attack surface: it lists every path,
method, parameter and authentication scheme the service accepts, which is
exactly what an attacker would otherwise have to guess.

The script requests a list of well-known document locations in a single
pipelined batch. For each one that answers with a document it reports the
specification version, the API title and version, the servers the API declares,
how many paths and operations it exposes, and the security schemes it defines.
With <code>showpaths</code> it also lists the operations. YAML documents are
recognized too, though only their title and version are extracted.

Only GET requests for documentation paths are sent, and no operation described
by the document is ever called.
]]

---
-- @usage nmap -p 80,443 --script http-openapi-discover <target>
-- @usage nmap -p 8080 --script http-openapi-discover --script-args http-openapi-discover.showpaths <target>
--
-- @args http-openapi-discover.path A single path to request instead of the
--       built-in list.
-- @args http-openapi-discover.paths A comma-separated list of paths to request
--       instead of the built-in list.
-- @args http-openapi-discover.showpaths If set, list the operations the
--       document declares, as method and path.
-- @args http-openapi-discover.maxpaths Maximum number of operations to list
--       when showpaths is set. Default: 50.
-- @args http-openapi-discover.all If set, report every document found. By
--       default only the first one is reported (all the candidate paths are
--       requested either way, in one pipelined batch).
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | http-openapi-discover:
-- |   /openapi.json:
-- |     spec: OpenAPI 3.0.3
-- |     title: Payments API
-- |     api_version: 2.4.1
-- |     paths: 37
-- |     operations: 58
-- |     servers:
-- |       https://api.example.com/v2
-- |     security_schemes:
-- |       apiKey (apiKey)
-- |_      bearerAuth (http)
--
-- @xmloutput
-- <table key="/openapi.json">
--   <elem key="spec">OpenAPI 3.0.3</elem>
--   <elem key="title">Payments API</elem>
--   <elem key="api_version">2.4.1</elem>
--   <elem key="paths">37</elem>
--   <elem key="operations">58</elem>
--   <table key="servers">
--     <elem>https://api.example.com/v2</elem>
--   </table>
--   <table key="security_schemes">
--     <elem>apiKey (apiKey)</elem>
--     <elem>bearerAuth (http)</elem>
--   </table>
-- </table>

author = "Nmap contributors"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"discovery", "safe"}

portrule = shortport.http

-- A description document can be large. Accept a truncated body rather than
-- failing: even a prefix tells us the API is exposed and usually carries the
-- title and version.
local MAX_BODY = 4 * 1024 * 1024

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

  return openapi.DEFAULT_PATHS
end

action = function(host, port)
  local paths = candidate_paths()
  local options = {
    showpaths = stdnse.get_script_args(SCRIPT_NAME .. ".showpaths") ~= nil,
    maxpaths = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".maxpaths")) or 50,
  }
  local find_all = stdnse.get_script_args(SCRIPT_NAME .. ".all") ~= nil

  local request_options = {
    max_body_size = MAX_BODY,
    truncated_ok = true,
    redirect_ok = false,
  }

  local requests = nil
  for _, path in ipairs(paths) do
    requests = http.pipeline_add(path, request_options, requests, "GET")
  end

  local responses = http.pipeline_go(host, port, requests)
  if not responses then
    stdnse.debug1("No response to any of the %d requests.", #paths)
    return nil
  end

  local output = stdnse.output_table()
  local found = 0

  for i, response in ipairs(responses) do
    local path = paths[i]
    if response and response.status == 200 and response.body and #response.body > 0 then
      local entry
      local doc, info = openapi.parse(response.body)

      if doc then
        entry = openapi.describe(doc, options)
      elseif info then
        -- YAML, or a JSON body that did not arrive whole.
        entry = stdnse.output_table()
        entry.spec = info.spec
        entry.title = info.title
        entry.api_version = info.api_version
        if response.truncated then
          entry.note = "document truncated; reported from the received prefix"
        end
      end

      if entry then
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

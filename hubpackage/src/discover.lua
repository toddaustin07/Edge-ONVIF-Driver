--[[
  Copyright 2022 Todd Austin

  Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file
  except in compliance with the License. You may obtain a copy of the License at:

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software distributed under the
  License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
  either express or implied. See the License for the specific language governing permissions
  and limitations under the License.


  DESCRIPTION
  
  ONVIF Discovery


--]]

local cosock = require "cosock"
local socket = require "cosock.socket"

local log = require "log"

local common = require "common"

local multicast_ip = "239.255.255.250"
local multicast_port = 3702
local listen_ip = "0.0.0.0"
local listen_port = 0

local ids_found = {}                -- used to filter duplicate usn's during discovery

local APP_MAX_DELAY = 500

-- multicast WSdiscovery query
local discover0 = [[
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing">
	<s:Header>
		<a:Action s:mustUnderstand="1">
			http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe
		</a:Action>
		<a:MessageID>uuid:bd26a53c-c043-4e00-9d2e-d8469c7808ee</a:MessageID>
		<a:ReplyTo><a:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo>
		<a:To s:mustUnderstand="1">urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To>
	</s:Header>
	<s:Body>
		<Probe xmlns="http://schemas.xmlsoap.org/ws/2005/04/discovery">
			<d:Types xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:dp0="http://www.onvif.org/ver10/network/wsdl">
				dp0:NetworkVideoTransmitter
			</d:Types>
		</Probe>
	</s:Body>
</s:Envelope>
]]


local function parse(data)

  local metadata = {}

  local parsed_xml = common.xml_to_table(data)
  
  if parsed_xml then
  
    parsed_xml = common.strip_xmlns(parsed_xml)
    
    --common.disptable(parsed_xml, '  ', 12)
    if parsed_xml['Envelope'] then
    
      if parsed_xml['Envelope']['Body']['ProbeMatches'] then
        metadata.uri = {}
        
	local service_addrs = parsed_xml['Envelope']['Body']['ProbeMatches']['ProbeMatch']['XAddrs']
	for addr in service_addrs:gmatch('[^ ]+') do
	  local ipv4 = addr:match('^(http://)([%d%.:]+)/')
	  if ipv4 then
	    metadata.uri.device_service = addr
	  end
	end
	
	if not metadata.uri.device_service then
	  log.error ('Could not find device service IPV4 address')
	end
	
	metadata.scopes = {}
	metadata.profiles = {}
        local scopestring = parsed_xml['Envelope']['Body']['ProbeMatches']['ProbeMatch']['Scopes']
        for item in scopestring:gmatch('[^ ]+') do
          table.insert(metadata.scopes, item)
          if item:find('/name/') then
            metadata.vendname = item:match('/name/(.+)$')
          elseif item:find('/location/') then
            metadata.location = item:match('/location/(.+)$')
          elseif item:find('/hardware/') then
            metadata.hardware = item:match('/hardware/(.+)$')
          elseif item:find('/Profile/') then
	    table.insert(metadata.profiles, item:match('/Profile/(.+)$'))
          end
        end
        metadata.urn = parsed_xml['Envelope']['Body']['ProbeMatches']['ProbeMatch']['EndpointReference']['Address']
	return metadata
        
      elseif parsed_xml['Envelope']['Body']['Fault'] then
	log.error ('SOAP ERROR:', parsed_xml['Envelope']['Body']['Fault']['Reason']['Text'][1])
      else
	log.error ('Unexpected discovery response:', data)
      end
		
    else
      log.error ("Unexpected discovery response - missing 'Envelope'", data)
    end
  else
    log.error ('Invalid XML returned in discovery response:', data)
  end
	
end


-- Use multicast to search for and discover devices
local function discover (waitsecs, callback, reset)

  if reset then; ids_found = {}; end

  -- initialize multicast socket

  local s = assert(socket.udp(), "create discovery socket")
  assert(s:setsockname(listen_ip, listen_port), "discovery socket setsockname")

  local timeouttime = socket.gettime() + waitsecs + .5 -- + 1/2 for network delay

  s:sendto(discover0, multicast_ip, multicast_port)

  while true do
    local time_remaining = math.max(0, timeouttime-socket.gettime())
    
    s:settimeout(time_remaining)
    
    local data, rip, port = s:receivefrom()

    if data then
    
      log.debug (string.format('Discovery response from: %s', rip))
      
      local cam_meta = parse(data)
      
      if cam_meta then
      
	local streamprofile
	for _, profile in ipairs(cam_meta.profiles) do
	  if profile == 'Streaming' then
	    streamprofile = profile
	  end
	end
	if streamprofile then
          cam_meta.ip = rip
          cam_meta.port = port
          cam_meta.addr = rip .. ':' .. tostring(port)

          callback(cam_meta)
          
        else
          log.warn ('No Streaming profile in discovered device')
        end
      end

    elseif rip == "timeout" then
        break

    else
      log.error ('ERROR:', rip)
    end

  end

  s:close()
    
end


return {
  discover = discover,

}

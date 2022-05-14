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

local Thread = require "st.thread"
local log = require "log"

local common = require "common"

local multicast_ip = "239.255.255.250"
local multicast_port = 3702
local listen_ip = "0.0.0.0"
local listen_port = 0

local ids_found = {}                -- used to filter duplicate usn's during discovery
local unfoundlist = {}
local rediscovery_thread
local rediscover_timer

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
    
    if parsed_xml['Envelope'] then
    
      if common.is_element(parsed_xml, {'Envelope', 'Body', 'ProbeMatches'}) then
      
	common.disptable(parsed_xml['Envelope']['Body']['ProbeMatches'], '  ', 10)
      
        metadata.uri = {}
        
	local service_addrs = parsed_xml['Envelope']['Body']['ProbeMatches']['ProbeMatch']['XAddrs']
	for addr in service_addrs:gmatch('[^ ]+') do
	
	  -- Address format possibilities:
	  --  IPV4: http://192.168.0.64/onvif/device_service
	  --  IPV6: http://[fe80::66db:8bff:fe61:56da]/onvif/device_service
	  --  hostname:  http://AminDSNEW:5357/a0d7119e-8b35-42a2-8db9-d7a26ab0b761
	
	  -- is it an IPV4 address?
	  local ipv4 = addr:match('^(http://)([%d%.:]+)/')
	  if ipv4 then
	    metadata.uri.device_service = addr
	    break
	  end
	  
	  -- is it a host name?
	  local hostname = addr:match('^(http://)([%w:]+)/')
	  if hostname then
	    metadata.uri.device_service = addr
	    break
	  end
	end
	
	if not metadata.uri.device_service then
	  log.error ('Could not find device service IPV4 address')
	end
	
	metadata.scopes = {}
	metadata.profiles = {}
	metadata.vendname = ''
	metadata.location = ''
	metadata.hardware = ''
	
	if common.is_element(parsed_xml, {'Envelope', 'Body', 'ProbeMatches', 'ProbeMatch', 'Scopes'}) then
	
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
	else
	  log.warn ('No Scopes found in discovery response')
	end
	
	if common.is_element(parsed_xml, {'Envelope', 'Body', 'ProbeMatches', 'ProbeMatch', 'EndpointReference', 'Address'}) then
	  metadata.urn = parsed_xml['Envelope']['Body']['ProbeMatches']['ProbeMatch']['EndpointReference']['Address']
	else
	  log.warn ('EndpointReference Address not found in discovery response')
	end
	
	return metadata
        
      elseif common.is_element(parsed_xml, {'Envelope', 'Body', 'Fault'}) then
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

  local sendmsg = common.compact_XML(discover0)

  s:sendto(sendmsg, multicast_ip, multicast_port)

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
	
	if not streamprofile then
	  log.warn ('No Streaming profile identified by discovered device')
        end
	
	cam_meta.ip = rip
	cam_meta.port = port
	cam_meta.addr = rip .. ':' .. tostring(port)

	callback(cam_meta)
          
      end

    elseif rip == "timeout" then
        break

    else
      log.error ('ERROR:', rip)
    end

  end

  s:close()
    
end


-- Scheduled re-discover retry routine for unfound devices (stored in unfoundlist table)
local function proc_rediscover()

  if next(unfoundlist) ~= nil then
  
    log.debug ('Running periodic re-discovery process for uninitialized devices:')
    for device_network_id, table in pairs(unfoundlist) do
      log.debug (string.format('\t%s (%s)', device_network_id, table.device.label))
    end
  
    discover(5, function (ipcam)

		  for device_network_id, table in pairs(unfoundlist) do
		    
		    if device_network_id == ipcam.urn then
		    
		      local device = table.device
		      local callback = table.callback
		      
		      log.info (string.format('Known device <%s (%s)> re-discovered at %s', ipcam.urn, device.label, ipcam.ip))
		      
		      local devmeta = device:get_field('onvif_disco')
		      devmeta.uri = ipcam.uri
		      devmeta.ip = ipcam.ip
		      devmeta.vendname = ipcam.vendname
		      devmeta.hardware = ipcam.hardware
		      devmeta.location = ipcam.location
		      devmeta.profiles = ipcam.profiles
		      devmeta.urn = ipcam.urn
		      device:set_field('onvif_disco', ipcam, {['persist'] = true })
		      
		      unfoundlist[device_network_id] = nil
		      callback(device)
		    end
		  end
		end,
		true			-- reset prior discovered device list to force re-finding
	    )
	    
     -- give discovery some time to finish
    socket.sleep(10)
    -- Reschedule this routine again if still unfound devices
    if next(unfoundlist) ~= nil then
      rediscover_timer = rediscovery_thread:call_with_delay(50, proc_rediscover, 're-discover routine')
    else
      rediscovery_thread:close()
    end
  end
end


local function schedule_rediscover(driver, device, delay, callback)
  
  if next(unfoundlist) == nil then
    unfoundlist[device.device_network_id] = { ['device'] = device, ['callback'] = callback }
    log.warn ('\tScheduling re-discover routine for later')
    if not rediscovery_thread then
      rediscovery_thread = Thread.Thread(driver, 'rediscover thread')
    end
    rediscover_timer = rediscovery_thread:call_with_delay(delay, proc_rediscover, 're-discover routine')
  else
    unfoundlist[device.device_network_id] = { ['device'] = device, ['callback'] = callback }
  end

end


return {
  discover = discover,
  schedule_rediscover = schedule_rediscover,
}

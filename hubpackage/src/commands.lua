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
  
  Implement ONVIF Network Device Operations (client)


--]]

local cosock = require "cosock"
local socket = require "cosock.socket"
local http = require "socket.http"
http.TIMEOUT = 5

local ltn12 = require "ltn12"
local log = require "log"

local common = require "common"
local auth = require "auth"
local uuid = require "uuid"


local function compact_XML(xml_in)

	local function nextchar(xml, index)
	
		local idx = index
		local char
		
		repeat
			char = string.sub(xml, idx, idx)
			if (char ~= ' ') and (char ~= '\t') and (char ~= '\n') then
				return char, idx
			else
				idx = idx + 1
			end
		until idx > #xml
	end

	local xml_out = ''
	local element_index = 1
	local char, lastchar
	local doneflag

	repeat
		doneflag = false
		lastchar = ''
	
		char, element_index = nextchar(xml_in, element_index)
		
		if not char then; break; end
		
		if char == '<' then

			-- Parse < > element
			repeat
				char = string.sub(xml_in, element_index, element_index)
				if char ~= '\n' then
					if char == '\t' then; char = ' '; end
					
					if (char == ' ') and (lastchar == ' ') then
						char = ''
					end
					
					if char ~= '' then
						lastchar = char
					else
						lastchar = ' '
					end
					
					xml_out = xml_out .. char
					if char == '>' then
						doneflag = true
					end
				end
				element_index = element_index + 1
			until doneflag or (element_index > #xml_in)
			
		else
			-- Parse data item element
			repeat
				char = string.sub(xml_in, element_index, element_index)
				if (char ~= ' ') and (char ~= '\t') and (char ~= '\n') then
					if char == '<' then
						doneflag = true
						break
					end
					xml_out = xml_out .. char
				end
				element_index = element_index + 1
			until doneflag or (element_index > #xml_in)
		end
		
	until element_index > #xml_in
	
	return xml_out					

end


local function parse_XMLresponse(data)

  local parsed_xml = common.xml_to_table(data)
  
  if parsed_xml then
  
    parsed_xml = common.strip_xmlns(parsed_xml)
  
		if parsed_xml['Envelope'] then
    
      if common.is_element(parsed_xml, {'Envelope', 'Body', 'Fault'}) then

        local fault_text = ''

        if parsed_xml['Envelope']['Body']['Fault'].faultcode then
          fault_text = parsed_xml['Envelope']['Body']['Fault'].faultstring
          log.warn ('SOAP ERROR:', parsed_xml['Envelope']['Body']['Fault'].faultcode, fault_text)
        else
          fault_text = parsed_xml['Envelope']['Body']['Fault']['Reason']['Text'][1]
          log.warn ('SOAP ERROR:', fault_text)
        end
        return nil, nil, fault_text
    
      else
        return parsed_xml['Envelope']['Header'], parsed_xml['Envelope']['Body']
      end
      
    else
      log.error ("Unexpected XML - missing 'Envelope'")
    end
  end
end


local function onvif_cmd(sendurl, command, sendbody, authheader)

  local responsechunks = {}

  local ret, code, headers, status
 
  if sendbody then
  
    local content_type = 'application/soap+xml; charset=utf-8'
    
    if (command == 'GetSystemDateAndTime') or
       (command == 'GetScopes') or
       (command == 'GetDeviceInformation') or
       (command == 'GetCapabilities') then
       
      content_type = content_type .. '; action="http://www.onvif.org/ver10/device/wsdl/' .. command .. '"'
       
    elseif (command == 'GetVideoSources') or
           (command == 'GetProfiles') or
           (command == 'GetStreamUri') then
           
      content_type = content_type .. '; action="http://www.onvif.org/ver10/media/wsdl/' .. command .. '"'
      
    end
    
    sendbody = compact_XML(sendbody)
         
    local sendheaders = {
													["Content-Type"] = content_type,
                          ["Host"] = sendurl:match('//([%d.:]+)/'),
                          ["Acccept"] = 'gzip, deflate',
                          ["Content-Length"] = #sendbody,
                          ["Connection"] = 'close',
                        }
    
    if authheader then
      sendheaders['Authorization'] = authheader
    end
    
    log.debug (string.format('Sending %s request to %s', command, sendurl))                    

    --[[
    log.debug ('Send headers:')
    for key, value in pairs(sendheaders) do
      log.debug (string.format('\t%s: %s', key, value))
    end
    --]]
                        
    ret, code, headers, status = http.request {
      method = 'POST',
      url = sendurl,
      headers = sendheaders,
      source = ltn12.source.string(sendbody),
      sink = ltn12.sink.table(responsechunks)
    }   
    
  else
    local sendheaders = {
                          ["Accept"] = '*/*'
                        }
    if authheader then
      sendheaders['Authorization'] = authheader
    end
    
    ret, code, headers, status = http.request {
      method = req_method,
      url = sendurl,
      sink = ltn12.sink.table(responsechunks),
      headers = sendheaders
    }
    
  end

  local response = table.concat(responsechunks)
  
  log.debug ('HTTP Response Header:', status)
  --[[
  if headers then
    for key, value in pairs(headers) do
      log.debug (string.format('\t%s: %s',key, value))
    end
  end
  --]]
  
  if ret then
    if code == 200 then
      return true, code, response, headers
    end
  end
      
  if (code ~= 400) and (code ~= 401) then
  
    if #response > 0 then
  
      local xmlhead, xmlbody, fault_text = parse_XMLresponse(response)
      
      if xmlbody then
        common.disptable(xmlbody, '  ', 8)
      else
        log.debug (response)
      end
    end
  end
  
  return false, code, response, headers
  
end


local function parse_authenticate(headers)

  for key, value in pairs(headers) do
    if string.lower(key) == 'www-authenticate' then
      return(value)
    end
  end

end


local function create_authdata_table(authrecord)

  local authtype, parms = authrecord:match('^(%a+) (.+)$')
        
  local authdata = {}
  authdata.type = authtype
  authdata.qop = parms:match('qop="([^"]+)"')
  authdata.realm = parms:match('realm="([^"]+)"')
  authdata.nonce = parms:match('nonce="([^"]+)"')
  authdata.algorithm = parms:match('algorithm="([^"]+)"')
  authdata.stale = parms:match('stale="([^"]+)"')
  authdata.opaque = parms:match('opaque="([^"]+)"')
  authdata.domain = parms:match('domain="([^"]+)"')
  
  return authdata

end

local function update_nonce(authinfo, headers)

  for key, value in pairs(headers) do
    if string.lower(key) == 'authentication-info' then
      
      if authinfo.authdata then
        authinfo.authdata.nonce = value:match('nextnonce="([^"]+)"')
        return authinfo
      else
        log.error ('Cannot update nextnonce; authdata table is missing')
      end
    end
  end
  
end

local function add_XML_header(xml, item)

  local insert_point = xml:find('  </s:Header>', 1, 'plaintext')
  return (xml:sub(1, insert_point - 1) .. item .. xml:sub(insert_point, #xml))

end


local function augment_header(request, url)

  local to = '    <wsa:To s:mustUnderstand="1">' .. url .. '</wsa:To>'
  
  local msgid = '<wsa:MessageID>urn:uuid:' .. uuid() .. '</wsa:MessageID>\n'
  
  request = add_XML_header(request, to)
  request = add_XML_header(request, msgid)
  
  return request

end

local function check_offline(device, code)

  if string.lower(code):find('no route to host', 1, 'plaintext') then
  
    device:set_field('onvif_online', false)
     
  end
end


local function get_new_auth(device, reqname, serviceURI, request)

  local authinited = false

  -- send request with no authentication

  local success, code, response, headers = onvif_cmd(serviceURI, reqname, request)
  
  if response then
  
    local xml_head, xml_body, fault_text = parse_XMLresponse(response)
    
    -- If error (expected), determine authorization method
    
    if code == 400 then             -- could be WSS authorization is required
      if string.lower(fault_text):find('not authorized', 1, 'plaintext') then
        auth_request = add_XML_header(request, auth.build_UsernameToken(device))
        authinited = true
      else
        log.error ('HTTP Error: 400 Bad Request; unknown authentication method')
        return
      end
      
    elseif code == 401 then         -- HTTP authorization is required
      
      local auth_record = parse_authenticate(headers)
      
      if auth_record then
      
        local authdata = create_authdata_table(auth_record)
        
        auth_header = auth.build_authheader(device, "POST", serviceURI, authdata)
        
        if auth_header then
          auth_request = request
          authinited = true
        end
      else
        log.error ('HTTP 401 returned without WWW-Authenticate header; unknown authentication method')
        return
      end
    else
      log.error (string.format('Unexpected HTTP Error %s from camera: %s', code, device.label))
      return
    end
  else
    log.error (string.format('No response data from camera (HTTP code %s)', device.label, code))
    check_offline(device, code)
    return
  end

  if authinited then
    return device:get_field('onvif_authinfo'), auth_header, auth_request
  end

end


local function _send_request(device, serviceURI, reqname, auth_request, auth_header)

  local success, code, response, headers = onvif_cmd(serviceURI, reqname, auth_request, auth_header)
  
  if (code == 200) and response then

    -- HTTP authenticating devices may return a new nonce to use in next request
    local authinfo = device:get_field('onvif_authinfo')
    if authinfo.type == 'http' then
      local newauthinfo = update_nonce(authinfo, headers)
      if newauthinfo then
        authinfo = newauthinfo
        device:set_field('onvif_authinfo', authinfo)
      end
    end
  end
  
  return success, code, response, headers

end


local function send_request(device, reqname, serviceURI, request)
  
  local auth_request
  local auth_header
  local authtype
  
  local authinfo = device:get_field('onvif_authinfo')

  if authinfo == nil then
  
    -- Need to build authentication 
    authinfo, auth_header, auth_request = get_new_auth(device, reqname, serviceURI, request)
  
    if not authinfo then
      log.error ('Failed to determine authentication method')
      return
    end
    
  else
  
    -- Authentication previously obtained
    if authinfo.type == 'wss' then
      auth_request = add_XML_header(request, auth.build_UsernameToken(device))
      auth_header = nil
    
    elseif authinfo.type == 'http' then
      if authinfo.authdata then
        auth_header = auth.build_authheader(device, "POST", serviceURI, authinfo.authdata)
        auth_request = request
      else
        log.error ('Missing HTTP authorization data')
        return
      end
    end
  end
  
  -- Authentication obtained; send request
    
  local success, code, response, headers = _send_request(device, serviceURI, reqname, auth_request, auth_header)
    
  --handle case where HTTP authenticating device may have sent new authentication headers
  if (code == 401) and (authinfo.type == 'http') then
  
    local auth_record = parse_authenticate(headers)
    
    if auth_record then
    
      local authdata = create_authdata_table(auth_record)
      
      auth_header = auth.build_authheader(device, "POST", serviceURI, authdata)
      
      success, code, response, headers = _send_request(device, serviceURI, reqname, auth_request, auth_header)
        
    else
      log.error ('Unexpected condition: HTTP 401 returned without WWW-Authenticate header')
      return
    end
    
  elseif (code == 400) and (authinfo.type == 'wss') then        -- not normally expected
    local xml_head, xml_body, fault_text = parse_XMLresponse(response)
    if fault_text then
      if string.lower(fault_text):find('not authorized', 1, 'plaintext') then
        auth_request = add_XML_header(request, auth.build_UsernameToken(device))
        auth_header = nil
      end
    else
      log.debug(response)
    end
  end
  
  if (code == 200) and response then
  
    local xml_head, xml_body, fault_text = parse_XMLresponse(response)
    
    if xml_body and not fault_text then
      return common.strip_xmlns(xml_body)
    
    elseif not xml_body then
      log.error (string.format('No XML body returned for %s request to camera %s', reqname, device.label))
    end
  else
    log.error (string.format('%s request failed with HTTP Error %s (camera %s)', reqname, code, device.label))
    check_offline(device, code)
  end

end

------------------------------------------------------------------------
--                        ONVIF COMMANDS
------------------------------------------------------------------------

local function GetSystemDateAndTime(device, device_serviceURI)

  local request = [[
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
    <GetSystemDateAndTime xmlns="http://www.onvif.org/ver10/device/wsdl"/>
  </s:Body>
</s:Envelope>
]]

  local success, code, response = onvif_cmd(device_serviceURI, 'GetSystemDateAndTime', request)
  
  if response then
  
    xml_head, xml_body = parse_XMLresponse(response)
    
    if xml_body then
    
      xml_body = common.strip_xmlns(xml_body)
    
      local cam_datetime = {}
    
      local cam_UTC_datetime = xml_body['GetSystemDateAndTimeResponse']['SystemDateAndTime']['UTCDateTime']
      cam_datetime.hour = tonumber(cam_UTC_datetime['Time']['Hour'])
      cam_datetime.min = tonumber(cam_UTC_datetime['Time']['Minute'])
      cam_datetime.sec = tonumber(cam_UTC_datetime['Time']['Second'])
      cam_datetime.month = tonumber(cam_UTC_datetime['Date']['Month'])
      cam_datetime.day = tonumber(cam_UTC_datetime['Date']['Day'])
      cam_datetime.year = tonumber(cam_UTC_datetime['Date']['Year'])
      
      local hub_datetime = os.date("!*t")
      log.info (string.format('Hub UTC datetime: %d/%d/%d %d:%02d:%02d', hub_datetime.month, hub_datetime.day, hub_datetime.year, hub_datetime.hour, hub_datetime.min, hub_datetime.sec))
      log.info (string.format('IP cam UTC datetime: %d/%d/%d %d:%02d:%02d', cam_datetime.month, cam_datetime.day, cam_datetime.year, cam_datetime.hour, cam_datetime.min, cam_datetime.sec))
      
      if (hub_datetime.year == cam_datetime.year) and 
         (hub_datetime.month == cam_datetime.month) and
         (hub_datetime.day == cam_datetime.day) then
      
        if hub_datetime.hour == cam_datetime.hour then
        
          local min_diff = math.abs(hub_datetime.min - cam_datetime.min)
          
          if min_diff > 5 then
            log.warn ('Time not synchronized:', device_serviceURI)
          end
        else
          log.warn ('Time not synchronized', device_serviceURI)
        end
      
      else
        log.warn ('Date not synchronized', device_serviceURI)
      end
         
      return cam_datetime
  
    end
  end
  
  log.error(string.format('Failed to get date/time from %s (%s)', device_serviceURI, device.label))
  check_offline(device, code)

end

local function GetScopes(device, device_serviceURI)

  local request = [[
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Header>
  </s:Header>
  <s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
		<GetScopes xmlns="http://www.onvif.org/ver10/device/wsdl"/>
	</s:Body>
</s:Envelope>
]]

  local xml_body = send_request(device, 'GetScopes', device_serviceURI, request)
  
  if xml_body then
  
    if xml_body['GetScopesResponse'] then
      
      local scopelist = {}
      
      for _, scope in ipairs(xml_body['GetScopesResponse']['Scopes']) do
        table.insert(scopelist, scope['ScopeItem'])
      end
      
      return scopelist
      
    else
      log.error ('Missing scopes response XML section')
    end
  end
  
  log.error(string.format('Failed to get Scopes from %s', device_serviceURI))

end


local function GetDeviceInformation(device, device_serviceURI)

  local request = [[
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Header>
  </s:Header>
	<s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
		<GetDeviceInformation xmlns="http://www.onvif.org/ver10/device/wsdl"/>
	</s:Body>
</s:Envelope>
]]

  local xml_body = send_request(device, 'GetDeviceInformation', device_serviceURI, request)
    
  if xml_body then
  
    if xml_body['GetDeviceInformationResponse'] then
      
      local infolist = {}
      
      for key, value in pairs(xml_body['GetDeviceInformationResponse']) do
        infolist[key] = value
      end
      
      return infolist
      
    else
      log.error ('Missing device info response XML section')
    end
  end
    
  log.error(string.format('Failed to get device info from %s', device_serviceURI))

end


local function GetCapabilities(device, device_serviceURI)

  local request = [[
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Header>
  </s:Header>
	<s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
    <GetCapabilities xmlns="http://www.onvif.org/ver10/device/wsdl">
			<Category>All</Category>
		</GetCapabilities>
	</s:Body>
</s:Envelope>
]]

  local xml_body = send_request(device, 'GetCapabilities', device_serviceURI, request)

  if xml_body then
  
    if common.is_element(xml_body, {'GetCapabilitiesResponse', 'Capabilities'}) then
      
        return xml_body['GetCapabilitiesResponse']['Capabilities']
        
    else
      log.error ('Missing capabilities XML from', device.label)
    end
  end
    
  log.error(string.format('Failed to get capabilities from %s', device_serviceURI))

end


local function GetVideoSources(device, media_serviceURI)

  local request = [[
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Header>
  </s:Header>
	<s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
    <GetVideoSources xmlns="http://www.onvif.org/ver10/media/wsdl"/>
	</s:Body>
</s:Envelope>
]]

  local xml_body = send_request(device, 'GetVideoSources', media_serviceURI, request)

  if xml_body then
  
    if common.is_element(xml_body, {'GetVideoSourcesResponse', 'VideoSources'}) then
      return xml_body['GetVideoSourcesResponse']['VideoSources']
    else
      log.error ('Missing video sources XML from', device.label)
    end
  end
  
  log.error(string.format('Failed to get video sources from %s', media_serviceURI))

end


local function GetProfiles(device, media_serviceURI)

  local request = [[
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Header>
  </s:Header>
	<s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
    <GetProfiles xmlns="http://www.onvif.org/ver10/media/wsdl"/>
	</s:Body>
</s:Envelope>
]]

  local xml_body = send_request(device, 'GetProfiles', media_serviceURI, request)

  if xml_body then
  
    if common.is_element(xml_body, {'GetProfilesResponse', 'Profiles'}) then
      return xml_body['GetProfilesResponse']['Profiles']
    else
      log.error ('Missing profiles response XML from', device.label)
    end
  end
    
  log.error(string.format('Failed to get profiles from %s', media_serviceURI))

end

local function GetStreamUri(device, token, media_serviceURI)

  local request_part1 = [[
<s:Envelope
    xmlns:s="http://www.w3.org/2003/05/soap-envelope"
    xmlns:trt="http://www.onvif.org/ver10/media/wsdl"
    xmlns:tt="http://www.onvif.org/ver10/schema">
  <s:Header>
  </s:Header>
  <s:Body>
    <trt:GetStreamUri>
      <trt:StreamSetup>
        <tt:Stream>
          RTP-Unicast
        </tt:Stream>
        <tt:Transport>
          <tt:Protocol>RTSP</tt:Protocol>
        </tt:Transport>
      </trt:StreamSetup>
      <trt:ProfileToken>]]
      
  local request_part2 = [[</trt:ProfileToken>
    </trt:GetStreamUri>
  </s:Body>
</s:Envelope>
]]

  local request = request_part1 .. token .. request_part2
  
  local xml_body = send_request(device, 'GetStreamUri', media_serviceURI, request)

  if xml_body then
  
    if common.is_element(xml_body, {'GetStreamUriResponse', 'MediaUri'}) then
      return xml_body['GetStreamUriResponse']['MediaUri']
    else
      log.error ('Missing stream URI XML from', device.label)
    end
  end
  
  log.error(string.format('Failed to get stream URI from %s', media_serviceURI))

end

------------------------------------------------------------------------
--                          EVENT-related
------------------------------------------------------------------------

local function GetEventProperties(device, event_serviceURI)

  local request = [[
<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope
    xmlns:s="http://www.w3.org/2003/05/soap-envelope"
    xmlns:wsa="http://www.w3.org/2005/08/addressing"
    xmlns:tet="http://www.onvif.org/ver10/events/wsdl">
  <s:Header>
    <wsa:Action>http://www.onvif.org/ver10/events/wsdl/EventPortType/GetEventPropertiesRequest</wsa:Action>
  </s:Header>
  <s:Body>
    <tet:GetEventProperties/>
  </s:Body>
</s:Envelope>
]]

  local xml_body = send_request(device, 'GetEventProperties', event_serviceURI, request)

  if xml_body then
  
    if common.is_element(xml_body, {'GetEventPropertiesResponse', 'TopicSet'}) then
      return xml_body['GetEventPropertiesResponse']['TopicSet']
    else
      log.error ('Missing topic set response XML from', device.label)
    end
  end
    
  log.error(string.format('Failed to get event properties from %s', event_serviceURI))

end


local function Subscribe(device, event_serviceURI, listenURI)

-- xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
-- <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope


  local request_part1 = [[
<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope
    xmlns:s="http://www.w3.org/2003/05/soap-envelope"
    xmlns:wsa="http://www.w3.org/2005/08/addressing"
    xmlns:wsnt="http://docs.oasis-open.org/wsn/b-2"
    xmlns:tet="http://www.onvif.org/ver10/events/wsdl"
    xmlns:tns1="http://www.onvif.org/ver10/topics"
    xmlns:tt="http://www.onvif.org/ver10/schema">
  <s:Header>
    <wsa:Action s:mustUnderstand="1">http://docs.oasis-open.org/wsn/bw-2/NotificationProducer/SubscribeRequest</wsa:Action>
    <wsa:ReplyTo><wsa:Address>http://www.w3.org/2005/08/addressing/anonymous</wsa:Address></wsa:ReplyTo>
  </s:Header>
  <s:Body>
    <wsnt:Subscribe>
      <wsnt:ConsumerReference>
        <wsa:Address>]]
        
    -- old action:  <wsa:Action>http://www.onvif.org/ver10/events/wsdl/NotificationProducer/SubscribeRequest</wsa:Action>
    -- WS XML Header alternatives:
    --   <wsa:Action>http://www.onvif.org/ver10/events/wsdl/NotificationProducer/SubscribeRequest</wsa:Action>
    --   <wsa:Action>http://docs.oasis-open.org/wsn/bw-2/NotificationProducer/SubscribeRequest</wsa:Action>

  local request_part2 = [[</wsa:Address>
      </wsnt:ConsumerReference>
      <tet:Filter>
        <wsnt:TopicExpression Dialect="http://www.onvif.org/ver10/tev/topicExpression/ConcreteSet">
          tns1:RuleEngine/CellMotionDetector//.
        </wsnt:TopicExpression>
      </tet:Filter>
      <wsnt:InitialTerminationTime>PT10M</wsnt:InitialTerminationTime>
    </wsnt:Subscribe>
  </s:Body>
</s:Envelope>
]]

--[[
      <tet:Filter>
        <wsnt:TopicExpression Dialect="http://www.onvif.org/ver10/tev/topicExpression/ConcreteSet">
          tns1:RuleEngine/CellMotionDetector//.
        </wsnt:TopicExpression>
        <wsnt:MessageContent Dialect="http://www.onvif.org/ver10/tev/messageContentFilter/ItemFilter">
          boolean(//tt:SimpleItem[@Name="IsMotion"])
        </wsnt:MessageContent>
      </tet:Filter>

      <wsnt:InitialTerminationTime>PT600S</wsnt:InitialTerminationTime>     example specified duration
      <wsnt:InitialTerminationTime xsi:nil="true"/>                         example permanant subscription
--]]

  local request = request_part1 .. listenURI .. request_part2
  
  request = augment_header(request, event_serviceURI)
  
  local xml_body = send_request(device, 'Subscribe', event_serviceURI, request)
    
  if xml_body then
  
    if xml_body['SubscribeResponse'] then
      return xml_body['SubscribeResponse']
    else
      log.error ('Missing subscribe response XML from', device.label)
    end
  end
  
  log.error(string.format('Failed to subscribe to %s', event_serviceURI))

end


local function RenewSubscription(device, event_source_addr, termtime)

  local request_part1 = [[
<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://www.w3.org/2005/08/addressing">
  <s:Header>
    <wsa:Action s:mustUnderstand="1">http://docs.oasis-open.org/wsn/bw-2/SubscriptionManager/RenewRequest</wsa:Action>
    <wsa:ReplyTo><wsa:Address>http://www.w3.org/2005/08/addressing/anonymous</wsa:Address></wsa:ReplyTo>
  </s:Header>
  <s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
    <Renew xmlns="http://docs.oasis-open.org/wsn/b-2"><TerminationTime>]]
    
  local request_part2 = [[</TerminationTime></Renew>
  </s:Body>
</s:Envelope>
]]

  local request = request_part1 .. termtime .. request_part2

  request = augment_header(request, event_source_addr)

  local xml_body = send_request(device, 'RenewSubscription', event_source_addr, request)
    
  if xml_body then
  
    if xml_body['RenewResponse'] then
      return xml_body['RenewResponse']
    else
      log.error ('Missing subscription renew response XML from', device.label)
    end
  end
  
  log.error(string.format('Failed to renew subscription to %s', event_serviceURI))

end


local function Unsubscribe(device)

  local request = [[
<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope
    xmlns:s="http://www.w3.org/2003/05/soap-envelope"
    xmlns:wsa="http://www.w3.org/2005/08/addressing"
    xmlns:wsnt="http://docs.oasis-open.org/wsn/b-2">
  <s:Header>
    <wsa:Action>http://docs.oasis-open.org/wsn/bw-2/SubscriptionManager/UnsubscribeRequest</wsa:Action>
    <wsa:ReplyTo><wsa:Address>http://www.w3.org/2005/08/addressing/anonymous</wsa:Address></wsa:ReplyTo>
  </s:Header>
  <s:Body><wsnt:Unsubscribe/></s:Body>
</s:Envelope>
]]

  local cam_func = device:get_field('onvif_func')

  if cam_func.event_source_addr then
    request = augment_header(request, cam_func.event_source_addr)
  
    local xml_body = send_request(device, 'Unsubscribe', cam_func.event_source_addr, request)
  
    if xml_body then; return true; end
    
    log.warn(string.format('Failed to unsubscribe to %s', cam_func.event_source_addr))
  end

end


local function CreatePullPointSubscription(device, event_serviceURI)

  local request = [[
<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope
    xmlns:s="http://www.w3.org/2003/05/soap-envelope"
    xmlns:wsa="http://www.w3.org/2005/08/addressing"
    xmlns:wsnt="http://docs.oasis-open.org/wsn/b-2"
    xmlns:tet="http://www.onvif.org/ver10/events/wsdl"
    xmlns:tns1="http://www.onvif.org/ver10/topics"
    xmlns:tt="http://www.onvif.org/ver10/schema">
  <s:Header>
    <wsa:Action s:mustUnderstand="1">
      http://www.onvif.org/ver10/events/wsdl/EventPortType/CreatePullPointSubscriptionRequest
    </wsa:Action>
  </s:Header>
  <s:Body>
    <tet:CreatePullPointSubscription xmlns="http://www.onvif.org/ver10/events/wsdl">
      <tet:InitialTerminationTime>PT1H</tet:InitialTerminationTime>
    </tet:CreatePullPointSubscription>
  </s:Body>
</s:Envelope>
]]

--[[
      <tet:Filter>
        <wsnt:TopicExpression Dialect="http://www.onvif.org/ver10/tev/topicExpression/ConcreteSet">
          tns1:RuleEngine/CellMotionDetector//.
        </wsnt:TopicExpression>
        <wsnt:MessageContent Dialect="http://www.onvif.org/ver10/tev/messageContentFilter/ItemFilter">
          boolean(//tt:SimpleItem[@Name="IsMotion"])
        </wsnt:MessageContent>
      </tet:Filter>
--]]

  local xml_body = send_request(device, 'CreatePullPointSubscription', event_serviceURI, request)
    
  if xml_body then
  
    if xml_body['CreatePullPointSubscriptionResponse'] then
      return xml_body['CreatePullPointSubscriptionResponse']
    else
      log.error ('Missing subscription response XML from', device.label)
    end
  end
  
  log.error(string.format('Failed to create pullpoint subscription to %s', event_serviceURI))

end


local function PullMessages(device, event_serviceURI)

  local request = [[
<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope
    xmlns:s="http://www.w3.org/2003/05/soap-envelope"
    xmlns:wsa="http://www.w3.org/2005/08/addressing"
    xmlns:tet="http://www.onvif.org/ver10/events/wsdl">
  <s:Header>
    <wsa:Action>http://www.onvif.org/ver10/events/wsdl/PullPointSubscription/PullMessagesRequest</wsa:Action>
  </s:Header>
  <s:Body>
    <tet:PullMessages>
      <tet:Timeout>PT1H</tet:Timeout>
      <tet:MessageLimit>30</tet:MessageLimit>
    </tet:PullMessages>
  <s:Body>
</s:Envelope>
]]

  local xml_body = send_request(device, 'PullMessages', event_serviceURI, request)
    
  if xml_body then
  
    if xml_body['PullMessagesResponse'] then
      return xml_body['PullMessagesResponse']
    else
      log.error ('Missing pull messages response XML from', device.label)
    end
  end
  
  log.error(string.format('Failed to pull messages from %s', event_serviceURI))

end


return {
          GetSystemDateAndTime = GetSystemDateAndTime,
          GetScopes = GetScopes,
          GetDeviceInformation = GetDeviceInformation,
          GetCapabilities = GetCapabilities,
          GetVideoSources = GetVideoSources,
          GetProfiles = GetProfiles,
          GetStreamUri = GetStreamUri,
          GetEventProperties = GetEventProperties,
          Subscribe = Subscribe,
          CreatePullPointSubscription = CreatePullPointSubscription,
          PullMessages = PullMessages,
          RenewSubscription = RenewSubscription,
          Unsubscribe = Unsubscribe,
}

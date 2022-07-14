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
local http = cosock.asyncify "socket.http"
http.TIMEOUT = 5

local ltn12 = require "ltn12"
local log = require "log"

local common = require "common"
local auth = require "auth"
local uuid = require "uuid"


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
    
    sendbody = common.compact_XML(sendbody)
         
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
      method = 'POST',
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
  
  if parms:match('algorithm="([^"]+)"') then
    authdata.algorithm = parms:match('algorithm="([^"]+)"')       -- should have no quotes according to spec
  else
    authdata.algorithm = parms:match('algorithm=([%w-]+)')
  end
  
  if parms:match('stale="([^"]+)"') then                          -- should have no quotes according to spec
    authdata.stale = parms:match('stale="([^"]+)"')
  else
    authdata.stale = parms:match('stale=([%a]+)')
  end
    
  authdata.opaque = parms:match('opaque="([^"]+)"')
  authdata.domain = parms:match('domain="([^"]+)"')
  
  --log.debug ('Authorization record:')
  --for key, value in pairs(authdata) do
  --  log.debug (string.format('\t%s: %s', key, value))
  --end
  
  return authdata

end

local function update_nonce(authinfo, headers)

  for key, value in pairs(headers) do
    if string.lower(key) == 'authentication-info' then

      --log.debug ('Response authentication-info:', value)
      if authinfo.authdata then
        local nextnonce = value:match('nextnonce="([^"]+)"')
        if nextnonce then
          authinfo.authdata.nonce = nextnonce
          return authinfo
        end
      else
        log.error ('Cannot update nextnonce; authdata table is missing')
      end
    end
  end
  
end


local function augment_header(request, url)

  local to = '    <wsa:To s:mustUnderstand="1">' .. url .. '</wsa:To>\n'
  
  local msgid = '    <wsa:MessageID>urn:uuid:' .. uuid() .. '</wsa:MessageID>\n'
  
  request = common.add_XML_header(request, to)
  request = common.add_XML_header(request, msgid)
  
  return request

end

local function check_offline(device, code)

  if code then
    if type(code) == 'string' then
      if string.lower(code):find('no route to host', 1, 'plaintext') or 
         string.lower(code):find('connection refused', 1, 'plaintext') or
         string.lower(code):find('timeout', 1, 'plaintext') then
      
        device:set_field('onvif_online', false)
         
      end
    end
  end
end


local function get_new_auth(device, reqname, serviceURI, request)

  local authinited = false
  local auth_header, auth_request

  -- send request with no authentication

  local success, code, response, headers = onvif_cmd(serviceURI, reqname, request)
  
  if response then
  
    if code == 200 then             -- Returned 200 OK; no authentication needed
      local authinfo = {}
      authinfo.type = 'none'
      device:set_field('onvif_authinfo', authinfo)
      return authinfo, nil, request, code, response
    
    else                            -- Error (expected), determine authorization method
      
      local xml_head, xml_body, fault_text = parse_XMLresponse(response)
      
      if code == 400 then             -- could be WSS authorization is required
        if string.lower(fault_text):find('not authorized', 1, 'plaintext') 
            or string.lower(fault_text):find('authority failure', 1, 'plaintext') then      -- TP Link
          auth_request = common.add_XML_header(request, auth.build_UsernameToken(device))
          authinited = true
        else
          log.error ('HTTP Error: 400 Bad Request; unknown authentication method')
          return
        end
        
      elseif code == 401 then         -- HTTP authorization is required
        
        local auth_record = parse_authenticate(headers)
        
        if auth_record then
        
          if auth_record:find('gSOAP Web Service', 1, 'plaintext') then
        
            -- Special case coming from Foscam R2 camera - treat as wss authentication type
            log.debug ('Assuming WS authentication')
            auth_request = common.add_XML_header(request, auth.build_UsernameToken(device))
            authinited = true
        
          else
            local authdata = create_authdata_table(auth_record)
            
            auth_header = auth.build_authheader(device, "POST", serviceURI, authdata)
            
            if auth_header then
              auth_request = request
              authinited = true
            end
          end
        else
          log.error ('HTTP 401 returned without WWW-Authenticate header; unknown authentication method')
          return nil, nil, nil, code
        end
      else
        log.error (string.format('Unexpected HTTP Error %s from camera: %s', code, device.label))
        return nil, nil, nil, code
      end

      if authinited then
        return device:get_field('onvif_authinfo'), auth_header, auth_request, code, response
      end

    end  
    
  else
    log.error (string.format('No response data from camera (HTTP code %s)', device.label, code))
    check_offline(device, code)
    return nil, nil, nil, code
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
  local http_code, http_response
  
  local authinfo = device:get_field('onvif_authinfo')

  if authinfo == nil then
  
    -- Need to build initial authentication 
    authinfo, auth_header, auth_request, http_code, http_response = get_new_auth(device, reqname, serviceURI, request)
  
    if not authinfo then
      log.error ('Failed to determine authentication method')
      return nil, http_code
    end
    
  else
  
    -- Authentication previously obtained
    if authinfo.type == 'wss' then
      auth_request = common.add_XML_header(request, auth.build_UsernameToken(device))
      auth_header = nil
    
    elseif authinfo.type == 'http' then
      if authinfo.authdata then
      
        auth_header = auth.build_authheader(device, "POST", serviceURI, authinfo.authdata)
        auth_request = request
      else
        log.error ('Missing HTTP authorization data')
        return
      end
    elseif authinfo.type == 'none' then
      auth_request = request
      auth_header = nil
    end
  end
  
  if http_code ~= 200 then          -- if we haven't already gotten back a successful response (without authentication)
  
    -- Send request with authentication
      
    local success, headers
    success, http_code, http_response, headers = _send_request(device, serviceURI, reqname, auth_request, auth_header)
      
    -- New authentication may be required
    if http_code == 401 then
    
      local auth_record = parse_authenticate(headers)
      
      if auth_record then
      
        if auth_record:find('gSOAP Web Service', 1, 'plaintext') then
        
          -- Special case coming from TP Link camera - needs to be wss authentication method
          log.debug ('Assuming WS authentication')
          auth_request = common.add_XML_header(request, auth.build_UsernameToken(device))
          auth_header = nil
          success, http_code, http_response, headers = _send_request(device, serviceURI, reqname, auth_request, auth_header)
          
        else
          local authdata = create_authdata_table(auth_record)
          
          if authinfo.type == 'none' then; device:set_field('onvif_authinfo', nil); end   -- reset authinfo
          
          auth_header = auth.build_authheader(device, "POST", serviceURI, authdata)
          
          success, http_code, http_response, headers = _send_request(device, serviceURI, reqname, auth_request, auth_header)
        end
      else
        log.error ('Unexpected condition: HTTP 401 returned without WWW-Authenticate header')
        return nil, http_code
      end
      
    elseif (http_code == 400) and ((authinfo.type == 'wss') or (authinfo.type == 'none')) then
      local xml_head, xml_body, fault_text = parse_XMLresponse(http_response)
      if fault_text then
        if string.lower(fault_text):find('not authorized', 1, 'plaintext')
            or string.lower(fault_text):find('authority failure', 1, 'plaintext') then      -- TP Link
          auth_request = common.add_XML_header(request, auth.build_UsernameToken(device))
          auth_header = nil
          success, http_code, http_response, headers = _send_request(device, serviceURI, reqname, auth_request, auth_header)
        else
          log.error('Unexpected SOAP fault')
        end
      else
        log.debug(http_response)
      end
    end
  end
  
  if (http_code == 200) and http_response then
  
    local xml_head, xml_body, fault_text = parse_XMLresponse(http_response)
    
    if xml_body and not fault_text then
      return common.strip_xmlns(xml_body), http_code
    
    elseif not xml_body then
      log.error (string.format('No XML body returned for %s request to camera %s', reqname, device.label))
    end
  else
    log.error (string.format('%s request failed with HTTP Error %s (camera %s)', reqname, http_code, device.label))
    log.debug (http_response)
    check_offline(device, http_code)
    return nil, http_code
  end

end

------------------------------------------------------------------------
--                        ONVIF COMMANDS
------------------------------------------------------------------------

local function GetSystemDateAndTime(device, device_serviceURI)

  local request = [[
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Header>
  </s:Header>
  <s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
    <GetSystemDateAndTime xmlns="http://www.onvif.org/ver10/device/wsdl"/>
  </s:Body>
</s:Envelope>
]]

  local xml_body, code = send_request(device, 'GetSystemDateAndTime', device_serviceURI, request)
  
  if xml_body then
  
    local cam_datetime = {}
    local datetime = {}
    local hub_datetime = os.date("!*t")
    local hub_epoch = os.time()
    
    datetime.hub = string.format('%d/%d/%d %d:%02d:%02d', hub_datetime.month, hub_datetime.day, hub_datetime.year, hub_datetime.hour, hub_datetime.min, hub_datetime.sec)
  
    if common.is_element(xml_body, {'GetSystemDateAndTimeResponse', 'SystemDateAndTime', 'UTCDateTime'}) then
      local cam_UTC_datetime = xml_body['GetSystemDateAndTimeResponse']['SystemDateAndTime']['UTCDateTime']
      cam_datetime.hour = tonumber(cam_UTC_datetime['Time']['Hour'])
      cam_datetime.min = tonumber(cam_UTC_datetime['Time']['Minute'])
      cam_datetime.sec = tonumber(cam_UTC_datetime['Time']['Second'])
      cam_datetime.month = tonumber(cam_UTC_datetime['Date']['Month'])
      cam_datetime.day = tonumber(cam_UTC_datetime['Date']['Day'])
      cam_datetime.year = tonumber(cam_UTC_datetime['Date']['Year'])
      
      local cam_epoch = os.time(cam_datetime)
      
      datetime.cam = string.format('%d/%d/%d %d:%02d:%02d', cam_datetime.month, cam_datetime.day, cam_datetime.year, cam_datetime.hour, cam_datetime.min, cam_datetime.sec)
      
      log.info (string.format('Hub UTC datetime: %s', datetime.hub))
      log.info (string.format('IP cam UTC datetime: %s', datetime.cam))
      
      if math.abs(hub_epoch - cam_epoch) > 300 then
        log.warn (string.format('Date/Time not synchronized with %s (%s)', device_serviceURI, device.label))
      end
         
      return datetime
      
    else
      if common.is_element(xml_body, {'GetSystemDateAndTimeResponse', 'SystemDateAndTime', 'DateTimeType'}) then
        if xml_body.GetSystemDateAndTimeResponse.SystemDateAndTime.DateTimeType == 'NTP' then
          datetime.cam = '(NTP)'
          return datetime
        end
      else
        log.error ('Missing date/time response in XML response')
        common.disptable(xml_body, '  ', 10)
      end
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


  local request_part1a = [[
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

  local request_part1b = [[</wsa:Address>
      </wsnt:ConsumerReference>
]]
  
    -- old action:  <wsa:Action>http://www.onvif.org/ver10/events/wsdl/NotificationProducer/SubscribeRequest</wsa:Action>
    -- WS XML Header alternatives:
    --   <wsa:Action>http://www.onvif.org/ver10/events/wsdl/NotificationProducer/SubscribeRequest</wsa:Action>
    --   <wsa:Action>http://docs.oasis-open.org/wsn/bw-2/NotificationProducer/SubscribeRequest</wsa:Action>

  local cellmotion_filter = [[
      <tet:Filter>
        <wsnt:TopicExpression Dialect="http://www.onvif.org/ver10/tev/topicExpression/ConcreteSet">
          tns1:RuleEngine/CellMotionDetector//.
        </wsnt:TopicExpression>
      </tet:Filter>
]]
  
  local motionalarm_filter = [[
      <tet:Filter>
        <wsnt:TopicExpression Dialect="http://www.onvif.org/ver10/tev/topicExpression/ConcreteSet">
          tns1:VideoSource/MotionAlarm//.
        </wsnt:TopicExpression>
      </tet:Filter>
]]

  local request_lastpart = [[
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

  local request
  
  local cam_info = device:get_field('onvif_info')
  if (cam_info.Manufacturer == 'TP-Link') and (cam_info.Model == 'C100') then   -- ****** TEMPORARY TEST ******
    request = request_part1a .. listenURI .. request_part1b .. request_lastpart
  
  elseif (device.preferences.motionrule == 'cell') or (device.preferences.motionrule == nil) then
    request = request_part1a .. listenURI .. request_part1b .. cellmotion_filter .. request_lastpart
  elseif device.preferences.motionrule == 'alarm' then
    request = request_part1a .. listenURI .. request_part1b .. motionalarm_filter .. request_lastpart
  else
    log.warn ('Unexpected motionrule setting value; no filter applied')
    request = request_part1a .. listenURI .. request_part1b .. request_lastpart
  end
  
  request = augment_header(request, event_serviceURI)
  
  --log.debug ('Subscribe request:')
  --log.debug (request)
  
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


local function gen_subid_header(device, request)

  local cam_func = device:get_field('onvif_func')
  if cam_func.subscriptionid then
    local subscription_header = '    <SubscriptionId wsa:IsReferenceParameter="true"'
    if cam_func.subscriptionid.attr then
      subscription_header = subscription_header .. ' xmlns=' .. cam_func.subscriptionid.attr:match('=(.+)$') .. ' xmlns:' .. cam_func.subscriptionid.attr
    end
    subscription_header = subscription_header .. '>' .. cam_func.subscriptionid.id .. '</SubscriptionId>\n'
    request = common.add_XML_header(request, subscription_header)
    
    --log.debug ('Subscription header:', subscription_header)
  end
  
  return request

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

  -- Add SubscriptionId XML header if needed (e.g. Axis cameras)
  request = gen_subid_header(device, request)
  
  request = augment_header(request, event_source_addr)
  
  local xml_body = send_request(device, 'RenewSubscription', event_source_addr, request)
    
  if xml_body then
  
    if xml_body['RenewResponse'] then
      return xml_body['RenewResponse']
    else
      log.error ('Missing subscription renew response XML from', device.label)
    end
  end
  
  log.error(string.format('Failed to renew subscription to %s', event_source_addr))

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
  
    -- Add SubscriptionId XML header if needed (e.g. Axis cameras)
    request = gen_subid_header(device, request)
  
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

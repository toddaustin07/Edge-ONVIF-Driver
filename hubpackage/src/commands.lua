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

local ltn12 = require "ltn12"
local log = require "log"

local common = require "common"
local auth = require "auth"


local function onvif_cmd(sendurl, command, sendbody)

  local responsechunks = {}

  local ret, code, headers, status
 
  if sendbody then
  
    local content_type = 'application/soap+xml; charset=utf-8'
    if command then
      content_type = content_type .. '; action="http://www.onvif.org/ver10/device/wsdl/' .. command .. '"'
    end
  
    local sendheaders = {
													["Content-Type"] = content_type,
                          ["Host"] = sendurl:match('//([%d.:]+)/'),
                          ["Acccept"] = 'gzip, deflate',
                          ["Content-Length"] = #sendbody,
                          ["Connection"] = 'close',
                        }
    log.debug (string.format('Sending %s request to %s', command, sendurl))
                        
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
    
    ret, code, headers, status = http.request {
      method = req_method,
      url = sendurl,
      sink = ltn12.sink.table(responsechunks),
      headers = sendheaders
    }
    
  end

  local response = table.concat(responsechunks)
  
  if ret then
    if code == 200 then
      return true, code, response
    end
  end
      
  log.error ('HTTP request failed:', ret, code, status)
  log.debug ('Headers:')
  for key, value in pairs(headers) do
    log.debug (string.format('\t%s: %s',key, value))
  end
  return false, code, response
  
end


local function parse_XMLresponse(data)

  local parsed_xml = common.xml_to_table(data)
  
  if parsed_xml then
    parsed_xml = common.strip_xmlns(parsed_xml)
  
		if parsed_xml['Envelope'] then
    
      if parsed_xml['Envelope']['Body'] then
        if parsed_xml['Envelope']['Body']['Fault'] then
          --common.disptable(parsed_xml['Envelope']['Body']['Fault'], '  ', 8)
          if parsed_xml['Envelope']['Body']['Fault'].faultcode then
            log.error ('SOAP ERROR:', parsed_xml['Envelope']['Body']['Fault'].faultcode, 
                                      parsed_xml['Envelope']['Body']['Fault'].faultstring)
          else
            log.error ('SOAP ERROR:', parsed_xml['Envelope']['Body']['Fault']['Reason']['Text'][1])
          end
          return nil, nil
        end
      end
    
      if parsed_xml['Envelope']['Header'] and parsed_xml['Envelope']['Body'] then
        return parsed_xml['Envelope']['Header'], parsed_xml['Envelope']['Body']
        
      elseif parsed_xml['Envelope']['Header'] then
        return parsed_xml['Envelope']['Header'], nil
        
      elseif parsed_xml['Envelope']['Body'] then
        return nil, parsed_xml['Envelope']['Body']
      end
      
    else
      log.error ("Unexpected XML - missing 'Envelope'")
    end
  end
end


local function GetSystemDateAndTime(device_serviceURI)

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
  
  log.error(string.format('HTTP error <%s> getting date/time from %s', code, device_serviceURI))

end

local function GetScopes(device, device_serviceURI)

  local request_part1 = [[
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
	<s:Header>
		<Security s:mustUnderstand="1" xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
]]

  local request_part2 = [[
    </Security>
	</s:Header>
	<s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
		<GetScopes xmlns="http://www.onvif.org/ver10/device/wsdl"/>
	</s:Body>
</s:Envelope>
]]

  local request = request_part1 .. auth.build_UsernameToken(device.preferences.userid, device.preferences.password) .. request_part2

  local success, code, response = onvif_cmd(device_serviceURI, 'GetScopes', request)
  
  if response then
  
    xml_head, xml_body = parse_XMLresponse(response)
    
    if xml_body then
    
      xml_body = common.strip_xmlns(xml_body)
      
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
    
  end
  
  log.error(string.format('HTTP error <%s> getting Scopes from %s', code, device_serviceURI))

end


local function GetDeviceInformation(device, device_serviceURI)

  local request_part1 = [[
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
	<s:Header>
		<Security s:mustUnderstand="1" xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
]]

  local request_part2 = [[
    </Security>
	</s:Header>
	<s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
		<GetDeviceInformation xmlns="http://www.onvif.org/ver10/device/wsdl"/>
	</s:Body>
</s:Envelope>
]]

  local request = request_part1 .. auth.build_UsernameToken(device.preferences.userid, device.preferences.password) .. request_part2

  local success, code, response = onvif_cmd(device_serviceURI, 'GetDeviceInformation', request)
  
  if response then
  
    xml_head, xml_body = parse_XMLresponse(response)
    
    if xml_body then
    
      xml_body = common.strip_xmlns(xml_body)
      
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
    
  end
  
  log.error(string.format('HTTP error <%s> getting device info from %s', code, device_serviceURI))

end


local function GetCapabilities(device, device_serviceURI)

    local request_part1 = [[
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
	<s:Header>
		<Security s:mustUnderstand="1" xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
]]

  local request_part2 = [[
    </Security>
	</s:Header>
	<s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
    <GetCapabilities xmlns="http://www.onvif.org/ver10/device/wsdl">
			<Category>All</Category>
		</GetCapabilities>
	</s:Body>
</s:Envelope>
]]

  local request = request_part1 .. auth.build_UsernameToken(device.preferences.userid, device.preferences.password) .. request_part2

  local success, code, response = onvif_cmd(device_serviceURI, 'GetCapabilities', request)

  if response then
  
    xml_head, xml_body = parse_XMLresponse(response)
    
    if xml_body then
    
      xml_body = common.strip_xmlns(xml_body)
      
      if xml_body['GetCapabilitiesResponse'] then
        if xml_body['GetCapabilitiesResponse']['Capabilities'] then
          return xml_body['GetCapabilitiesResponse']['Capabilities']
          
        else
          log.warn ('No capabilities returned')
        end
      else
        log.error ('Missing capbilities response XML section')
      end
    end
    
  end
  
  log.error(string.format('HTTP error <%s> getting capabilities from %s', code, device_serviceURI))

end

local function GetVideoSources(device, media_serviceURI)

    local request_part1 = [[
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
	<s:Header>
		<Security s:mustUnderstand="1" xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
]]

  local request_part2 = [[
    </Security>
	</s:Header>
	<s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
    <GetVideoSources xmlns="http://www.onvif.org/ver10/media/wsdl"/>
	</s:Body>
</s:Envelope>
]]

  local request = request_part1 .. auth.build_UsernameToken(device.preferences.userid, device.preferences.password) .. request_part2

  local success, code, response = onvif_cmd(media_serviceURI, 'wsdlGetVideoSources', request)

  if response then
  
    xml_head, xml_body = parse_XMLresponse(response)
    
    if xml_body then
    
      xml_body = common.strip_xmlns(xml_body)
      
      if xml_body['GetVideoSourcesResponse'] then
        return xml_body['GetVideoSourcesResponse']['VideoSources']
      else
        log.error ('Missing video sources response XML section')
      end
    end
    
  end
  
  log.error(string.format('HTTP error <%s> getting video sources from %s', code, media_serviceURI))

end


local function GetProfiles(device, media_serviceURI)

    local request_part1 = [[
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
	<s:Header>
		<Security s:mustUnderstand="1" xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
]]

  local request_part2 = [[
    </Security>
	</s:Header>
	<s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
    <GetProfiles xmlns="http://www.onvif.org/ver10/media/wsdl"/>
	</s:Body>
</s:Envelope>
]]

  local request = request_part1 .. auth.build_UsernameToken(device.preferences.userid, device.preferences.password) .. request_part2

  local success, code, response = onvif_cmd(media_serviceURI, 'GetProfiles', request)

  if response then
  
    xml_head, xml_body = parse_XMLresponse(response)
    
    if xml_body then
    
      xml_body = common.strip_xmlns(xml_body)
      
      if xml_body['GetProfilesResponse'] then
        return xml_body['GetProfilesResponse']['Profiles']
      else
        log.error ('Missing profiles response XML section')
      end
    end
    
  end
  
  log.error(string.format('HTTP error <%s> getting profile from %s', code, media_serviceURI))

end

local function GetStreamUri(device, token, media_serviceURI)

    local request_part1 = [[
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
	<s:Header>
		<Security s:mustUnderstand="1" xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
]]

    local request_part2 = [[
    </Security>
	</s:Header>
	<s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
    <GetStreamUri xmlns="http://www.onvif.org/ver10/media/wsdl">
			<StreamSetup>
				<Stream xmlns="http://www.onvif.org/ver10/schema">
					RTP-Unicast
				</Stream>
				<Transport xmlns="http://www.onvif.org/ver10/schema">
					<Protocol>RTSP</Protocol>
				</Transport>
			</StreamSetup>
			<ProfileToken>
]]

    local request_part3 = [[
</ProfileToken>
		</GetStreamUri>
	</s:Body>
</s:Envelope>
]]

  local request = request_part1 .. auth.build_UsernameToken(device.preferences.userid, device.preferences.password) .. request_part2

  request = request .. token .. request_part3

  local success, code, response = onvif_cmd(media_serviceURI, 'GetStreamUri', request)

  if response then
  
    xml_head, xml_body = parse_XMLresponse(response)
    
    if xml_body then
    
      xml_body = common.strip_xmlns(xml_body)
      
      if xml_body['GetStreamUriResponse'] then
        if xml_body['GetStreamUriResponse']['MediaUri'] then
          return xml_body['GetStreamUriResponse']['MediaUri']
        end
      end
      log.error ('Missing Stream URI response XML section')
    end
  end
  
  log.error(string.format('HTTP error <%s> getting stream uri from %s', code, media_serviceURI))

end

local function GetEventProperties(device, event_serviceURI)

  local request_part1 = [[
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
	<s:Header>
		<Security s:mustUnderstand="1" xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
]]

  local request_part2 = [[
    </Security>
	</s:Header>
	<s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
    <GetEventProperties xmlns="http://www.onvif.org/ver10/events/wsdl"/>
	</s:Body>
</s:Envelope>
]]

  local request = request_part1 .. auth.build_UsernameToken(device.preferences.userid, device.preferences.password) .. request_part2

  local success, code, response = onvif_cmd(event_serviceURI, 'GetEventProperties', request)

  if response then
  
    xml_head, xml_body = parse_XMLresponse(response)
    
    if xml_body then
    
      xml_body = common.strip_xmlns(xml_body)
      
      if xml_body['GetEventPropertiesResponse'] then
        if xml_body['GetEventPropertiesResponse']['TopicSet'] then
          return xml_body['GetEventPropertiesResponse']['TopicSet']
        else
          log.error ('Missing topic set in event properties response')
        end
      else
        log.error ('Missing event properties response XML section')
      end
    end
    
  end
  
  log.error(string.format('HTTP error <%s> getting event properties from %s', code, event_serviceURI))

end


local function SubscribeRequest(device, event_serviceURI, listenURI)

-- xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
-- <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope


   local request_part1 = [[
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
            xmlns:wsa="http://www.w3.org/2005/08/addressing"
            xmlns:wsnt="http://docs.oasis-open.org/wsn/b-2" >
	<s:Header>
    <wsa:Action>http://www.onvif.org/ver10/events/wsdl/NotificationProducer/SubscribeRequest</wsa:Action>
		<Security s:mustUnderstand="1" xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
]]

    -- <wsa:Action>http://www.onvif.org/ver10/events/wsdl/NotificationProducer/SubscribeRequest</wsa:Action>
    --  <wsa:Action>http://docs.oasis-open.org/wsn/bw-2/NotificationProducer/SubscribeRequest</wsa:Action>

  local request_part2 = [[
    </Security>
	</s:Header>
	<s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
    <wsnt:Subscribe>
      <wsnt:ConsumerReference>
        <wsa:Address>
]]

  local request_part3 = [[
        </wsa:Address>
      </wsnt:ConsumerReference>
      <wsnt:InitialTerminationTime>PT60M</wsnt:InitialTerminationTime>
    </wsnt:Subscribe>
	</s:Body>
</s:Envelope>
]]

      --<wsnt:InitialTerminationTime>PT600S</wsnt:InitialTerminationTime>
      --<wsnt:InitialTerminationTime xsi:nil="true"/>

  local request = request_part1 .. auth.build_UsernameToken(device.preferences.userid, device.preferences.password) .. request_part2
  request = request .. listenURI .. request_part3
  
  local success, code, response = onvif_cmd(event_serviceURI, nil, request)
  
  if response then
  
    xml_head, xml_body = parse_XMLresponse(response)
    
    if xml_body then
    
      xml_body = common.strip_xmlns(xml_body)
      
      if xml_body['SubscribeResponse'] then
          return xml_body['SubscribeResponse']
      else
        log.error ('Missing subscribe response XML section')
      end
    end
    
  end
  
  log.error(string.format('HTTP error <%s> subscribing to %s', code, event_serviceURI))

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
          SubscribeRequest = SubscribeRequest,
}

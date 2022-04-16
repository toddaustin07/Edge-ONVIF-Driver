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
  
  ONVIF Camera event handler

--]]

local cosock = require "cosock"
local socket = require "cosock.socket"
local http = cosock.asyncify "socket.http"
local ltn12 = require "ltn12"
local Thread = require "st.thread"
local log = require "log"

local commands = require "commands"
local common = require "common"

local initflag = false
local eventservers = {}

local eventing_thread

local DEFAULT_SUBSCRIBE_DURATION = 14400		


-- Handle event connections from device
local function eventaccept_handler(_, eventsock)

  local client, accept_err = eventsock:accept()

	if accept_err ~= nil then
		log.error ("Connection accept error: " .. accept_err)
		--eventsock:close()
		return
	end
	
	if client == nil then
		log.error ('Client connection for event is nil')
		return
	end
	
	client:settimeout(1)
	
	local data, err = client:receive('*a')
	if err == nil then
		if data then
			if data:find('<?xml', 1, 'plaintext') == 1 then
			
				local parsed_xml = common.xml_to_table(data)

				if parsed_xml then
					log.debug('Received event message')
					
					parsed_xml = common.strip_xmlns(parsed_xml)
					
					local eventserver
					for id, evntsrvr in pairs(eventservers) do
						if evntsrvr.sock == eventsock then
							eventserver = evntsrvr
						end
					end
					
					if eventserver then
					
						local founddata = false
						
						if common.is_element(parsed_xml, {'Envelope','Body','Notify','NotificationMessage','Message','Message','Data'}) then
						
							local msgdata = parsed_xml['Envelope']['Body']['Notify']['NotificationMessage']['Message']['Message']['Data']
							
							eventserver.callback(eventserver.device, msgdata)
							founddata = true
						end
						
						if not founddata then
							log.error ('Expected Event Message data not found')
						end
						
					else
						log.error ('No eventserver record found - cannot process')
					end
				else
					log.error ('Could not parse message XML')
				end
			else
				log.error ("Received unexpected prefix: " .. data)
			end
		else
			log.warn ("Received empty msg")
		end
	else
		log.error ("Event socket receive failed: " .. err)
	end
		
	client:close()

end


local function init(driver, eventserver)

	eventserver.sock = socket.tcp()

	-- create server on IP_ANY and os-assigned port
	assert(eventserver.sock:bind("*", 0))
	assert(eventserver.sock:listen(5))
	local ip, port, _ = eventserver.sock:getsockname()

	if ip ~= nil and port ~= nil then
		
		eventserver.listen_ip = ip
		eventserver.listen_port = port
		
		if not eventserver.eventing_thread then
			eventserver.eventing_thread = Thread.Thread(driver, 'event server thread')
		end
  
		eventserver.eventing_thread:register_socket(eventserver.sock, eventaccept_handler)
		log.info ("Event server started and listening on: " .. ip .. ":" .. port)

		return true
		
	else
		log.error ("Could not get IP/port from TCP getsockname(), not listening for events")
		eventserver.sock:close()
		eventserver.sock = nil
		return false
	end	
end


local renew_subscribe					-- forward reference

local function _do_subscribe(eventserver)

	local uri = string.format('http://%s:%s/event', eventserver.listen_ip, eventserver.listen_port)
	local device = eventserver.device
	
	log.info ('Subscribing to motion events for', device.label)
	
	local cam_func = device:get_field('onvif_func')
	
	local response = commands.SubscribeRequest(device, cam_func.event_service_addr, uri)
	
	if response then
	
		log.debug('Subscription response:')
		common.disptable(response, ' ', 10)
	
		if response['SubscriptionReference'] then
		
			local termination_time = response['TerminationTime']
			local current_time = response['CurrentTime']
			
			if termination_time and current_time then
				local t = {}
				t['year'], t['month'], t['day'], t['hour'], t['min'], t['sec'] = termination_time:match('^(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)Z')

				local c = {}
				c['year'], c['month'], c['day'], c['hour'], c['min'], c['sec'] = current_time:match('^(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)Z')
				
				eventserver.epoch_termination_time = os.time(t)
				local duration = eventserver.epoch_termination_time - os.time(c)
				
				local event_source_addr
				if response['SubscriptionReference']['Address'] then
					event_source_addr = response['SubscriptionReference']['Address']
				end
				
				eventserver.event_source_addr = event_source_addr
				
				log.info('Successfully subscribed to events for', device.label)
				log.info(string.format('\tDuration = %s minutes', duration/60))
				log.info('\tRef Address:', event_source_addr)
				
				local interval = duration - math.random(60, 180)
				local interval_min = math.modf(interval/60)
				local interval_sec = math.fmod(interval, 60)
				log.debug (string.format('Scheduling subscription renewal to run in %02d:%02d', interval_min, interval_sec))
				
				eventserver.renew_timer = device.thread:call_with_delay(interval, renew_subscribe , "Subscription renewal timer")
					
				return true
				
			else
				log.error ('Missing termination time from subscription response for', device.label)
			end
				
		else
			log.error ('Missing subscription reference section in subscription response')
			eventserver.epoch_termination_time = os.time() + DEFAULT_SUBSCRIBE_DURATION
		end
		
	else
		eventservers.device_network_id = nil
		log.error('Cannot subscribe to events')
	end

end


renew_subscribe = function()

	local currtime = os.time()
	
	for id, eventserver in pairs(eventservers) do
	
		if (currtime >= eventserver.epoch_termination_time) or
		   ((eventserver.epoch_termination_time - currtime) <= 180) then
		   
		   _do_subscribe(eventserver)
		   
		end
	end

end


local function subscribe(driver, device, eventname, callback)

	local eventserver
	local device_network_id = device.device_network_id
	
	for id, evntsrvr in pairs(eventservers) do
		if id	== device_network_id then
			eventserver = evntsrvr
		end
	end
	
	local continue = true
	
	if eventserver == nil then
		eventservers[device_network_id] = {}
		eventserver = eventservers[device_network_id]
		continue = init(driver, eventserver)
	end
	
	if continue then
	
		eventserver.device = device
		eventserver.eventname = eventname
		eventserver.callback = callback
		
		local cam_meta = device:get_field('onvif_disco')
		
		if not (cam_meta.ip) then
			log.error ('Camera IP not known; cannot subscribe to', device.label)
			return nil
		end

		if eventserver.listen_port == nil then
			log.error ("Cannot subscribe, no event listen server address available:", device.label)
			return nil
		end
		
		if not eventserver.sock then
			log.error ('No event server socket for', device.label)
			return nil
		end
		
		-- Event Listen Server initialization complete; now send subscribe request
		return _do_subscribe(eventserver)

	else
		log.error('Subscribe failed for', device.label)
	end
		
	return false

end

local function shutdownserver(driver, device)

	local device_network_id = device.device_network_id
	local eventserver
	
	for id, evntsrvr in pairs(eventservers) do
		if id	== device_network_id then
			eventserver = evntsrvr
		end
	end

	if eventserver then
		eventserver.eventing_thread:unregister_socket(eventserver.sock)
		eventserver.sock:close()
		eventserver.eventing_thread:close()
		driver:cancel_timer(eventserver.renew_timer)
		
		log.info ('Event server shutdown for device', device.label)
	end	
		
	eventservers[device_network_id] = nil
	
end

return {

	subscribe = subscribe,
	shutdownserver = shutdownserver,
}

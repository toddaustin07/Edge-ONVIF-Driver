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
  
  ONVIF Video camera driver for SmartThings Edge

--]]

-- Edge libraries
local capabilities = require "st.capabilities"
local Driver = require "st.driver"
local cosock = require "cosock"                   -- cosock used only for sleep timer in this module
local socket = require "cosock.socket"
local log = require "log"


-- Driver-specific libraries
local Thread = require "st.thread"
local classify = require "classify"
local Semaphore = require "semaphore"

local discover = require "discover"
local commands = require "commands"
local events = require "events"
local common = require "common"

-- Custom capabilities
local cap_status = capabilities["partyvoice23922.onvifstatus"]
local cap_info = capabilities["partyvoice23922.onvifinfo"]
local cap_refresh = capabilities["partyvoice23922.refresh"]
local cap_motion = capabilities["partyvoice23922.motionevents"]

-- Module Variables

local disco_sem

local onvifDriver = {}
local rediscovery_thread
local rediscover_timer
local resub_thread
local resub_timer

local newly_added = {}
local unfoundlist = {}
local discovered_num = 1

local swstate = {}

math.randomseed(socket.gettime())


local function disptable(table, tab, maxlevels, currlevel)

	if not currlevel then; currlevel = 0; end
  currlevel = currlevel + 1
  for key, value in pairs(table) do
    if type(key) ~= 'table' then
      log.debug (tab .. '  ' .. key, value)
    else
      log.debug (tab .. '  ', key, value)
    end
    if (type(value) == 'table') and (currlevel < maxlevels) then
      disptable(value, '  ' .. tab, maxlevels, currlevel)
    end
  end
end


local function build_html(list)

  local html_list = ''

  for itemnum, item in ipairs(list) do
    html_list = html_list .. '<tr><td>' .. item .. '</td></tr>\n'
  end

  local html =  {
                  '<!DOCTYPE html>\n',
                  '<HTML>\n',
                  '<HEAD>\n',
                  '<style>\n',
                  'table, td {\n',
                  '  border: 1px solid black;\n',
                  '  border-collapse: collapse;\n',
                  '  font-size: 11px;\n',
                  '  padding: 3px;\n',
                  '}\n',
                  '</style>\n',
                  '</HEAD>\n',
                  '<BODY>\n',
                  '<table>\n',
                  html_list,
                  '</table>\n',
                  '</BODY>\n',
                  '</HTML>\n'
                }
    
  return (table.concat(html))
end

local function is_array(t)
  if type(t) ~= "table" then return false end
  local i = 0
  for _ in pairs(t) do
    i = i + 1
    if t[i] == nil then return false end
  end
  return true
end

local function init_infolist(device, ipcam)

  local infolist = {}

  table.insert(infolist, 'IP addr: ' .. ipcam.ip)
  table.insert(infolist, 'Name: ' .. ipcam.vendname)
  table.insert(infolist, 'Hardware: ' .. ipcam.hardware)
  table.insert(infolist, 'Location: ' .. ipcam.location)
  for _, profile in ipairs(ipcam.profiles) do
    table.insert(infolist, 'Profile: ' .. profile)
  end
  table.insert(infolist, ipcam.urn)
  
  device:emit_component_event(device.profile.components.info, cap_info.info(build_html(infolist)))
  
  device:set_field('onvif_info', infolist)
  
  return infolist
end


local function event_handler(device, msg)

  log.debug ('Event handler invoked')
  
  local cam_func = device:get_field('onvif_func')
  
  if common.is_element(msg, {'SimpleItem','_attr','Name'}) then
  
    local name = msg['SimpleItem']._attr.Name
    local value = msg['SimpleItem']._attr.Value
    
    if name == cam_func.motion_event_name then
    
      log.info (string.format('Motion for %s = %s', device.label, value))
      
      if value == 'true' then
        device:emit_event(capabilities.motionSensor.motion('active'))
      else
        device:emit_event(capabilities.motionSensor.motion('inactive'))
      end
      
    else
      log.warn('Unrecognized event name ignored:', name)
    end
  else
    log.warn('Missing event item name XML section')
  end
end


local function get_cam_config(device)

  log.info('Starting Device Initialization routine for', device.label)
  
  local meta = device:get_field('onvif_disco')
  if meta then
    
    local infolist = init_infolist(device, meta)
    
    local cam_datetime = commands.GetSystemDateAndTime(meta.uri.device_service)
    
    if cam_datetime then
    
      device:emit_component_event(device.profile.components.info, cap_status.status('Responding'))
      --device:online()
      
      if (device.preferences.userid ~= '*****') and (device.preferences.password ~= '*****') then
        
        -- GET SCOPES --------------------------------------------------
        
        local scopes = commands.GetScopes(device, meta.uri.device_service)
        
        log.debug(string.format('Found scopes for %s:', device.label))
        
        local foundflag = false
        
        for _, scope in ipairs(scopes) do
          log.debug ('\t' .. scope)
          if not scope:match('^onvif') then
            table.insert(infolist, scope)
            foundflag = true
          end
        end
            
        if foundflag then
          device:emit_component_event(device.profile.components.info, cap_info.info(build_html(infolist)))
          device:set_field('onvif_info', infolist)
        end
        
        -- GET DEVICE INFO ---------------------------------------------
        
        local infotable = commands.GetDeviceInformation(device, meta.uri.device_service)
        
        for key, value in pairs(infotable) do
          log.debug ('\t' .. key, value)
          table.insert(infolist, key .. ': ' .. value)
        end
            
        device:emit_component_event(device.profile.components.info, cap_info.info(build_html(infolist)))
        device:set_field('onvif_info', infolist)
        
        -- GET CAPABILITIES --------------------------------------------
        
        local capabilities = commands.GetCapabilities(device, meta.uri.device_service)
        
        local onvif_func = {}
        
        if capabilities['Events'] then
          onvif_func.event_service_addr = capabilities['Events']['XAddr']
          onvif_func.PullPointSupport = capabilities['Events']['WSPullPointSupport']
        end
        
        if capabilities['Media'] then
          onvif_func.media_service_addr = capabilities['Media']['XAddr']
          if capabilities['Media']['StreamingCapabilities'] then
            onvif_func.RTP_TCP = capabilities['Media']['StreamingCapabilities']['RTP_TCP']
            onvif_func.RTP_RTSP_TCP = capabilities['Media']['StreamingCapabilities']['RTP_RTSP_TCP']
          end
        end
        
        device:set_field('onvif_func', onvif_func)
        
        -- GET VIDEO SOURCES -------------------------------------------
        
        local videosources = commands.GetVideoSources(device, onvif_func.media_service_addr)
        
        onvif_func.video_source_token = videosources._attr.token
        log.debug ('Video source token:', videosources._attr.token)
        
        device:set_field('onvif_func', onvif_func)
        
        -- GET PROFILE -------------------------------------------------
        
        local profiles = commands.GetProfiles(device, onvif_func.media_service_addr)
        
        local profilematch
        for _, profile in ipairs(profiles) do
          if profile._attr.token == onvif_func.video_source_token then
            profilematch = profile
          end
        end
        
        if profilematch ~= nil then
        
          -- GET STREAM URI---------------------------------------------
        
          local uri_info = commands.GetStreamUri(device, onvif_func.video_source_token, onvif_func.media_service_addr)
          
          onvif_func.stream_uri = uri_info['Uri']
          device:set_field('onvif_func', onvif_func)
          
          log.debug('Stream URI:', onvif_func.stream_uri)
        
        else
          log.error ('Could not find matching profile for token', onvif_func.video_source_token)
        end
        
        -- GET EVENT STUFF ---------------------------------------------
        
        local function parse_for_motion_rule(rule, name)
          disptable(rule, '  ', 12)
          
          if common.is_element(rule, {'CellMotionDetector','Motion','MessageDescription','Data','SimpleItemDescription','_attr','Name'}) then
        
            if rule['CellMotionDetector']['Motion']['MessageDescription']['Data']['SimpleItemDescription']._attr.Name == name then
              return true
            end
          end
          return false
        end
        
        local MOTIONRULENAME = 'IsMotion'         -- **** May vary by manufacturer! ****
        
        local event_properties = commands.GetEventProperties(device, onvif_func.event_service_addr)
        
        if event_properties['RuleEngine'] then
        
          log.debug('Is array?', is_array(event_properties['RuleEngine']))
          local motion_found = false
          
          if is_array(event_properties['RuleEngine']) then
            
            for _, rule in ipairs (event_properties['RuleEngine']) do
              if parse_for_motion_rule(rule, MOTIONRULENAME) then
                motion_found = true
              end
            end
            
          else
            motion_found = parse_for_motion_rule(event_properties['RuleEngine'], MOTIONRULENAME)
          end
                  
          if motion_found == true then
            log.debug (string.format('"%s" motion event property found', MOTIONRULENAME))
            onvif_func.motion_events = true
            onvif_func.motion_event_name = MOTIONRULENAME
          else
            onvif_func.motion_events = false
          end
          device:set_field('onvif_func', onvif_func)
          
          return true
        
        else
          log.error('Missing rule engine section in event properties response')
        
        end      
        
      else
        log.warn ('Userid/Password not configured:', device.label)
      end
      
    else
      device:emit_component_event(device.profile.components.info, cap_status.status('Not responding'))
      --device:offline()
    end
  
  else
    log.error ('Cannot initialize: persistent ONVIF discovery info missing')
  end

  return false
  
end


-- Here is where we perform all our device startup tasks
local function init_device(device)

  if get_cam_config(device) then
    
    if device:get_latest_state("main", cap_motion.ID, cap_motion.switch.NAME) == 'On' then
      if not events.subscribe(onvifDriver, device, device:get_field('onvif_func').motion_event_name, event_handler) then
        log.error ('Failed to subscribe to motion events', device.label)
        return
      end
    end
    log.info(string.format('%s successfully initialized', device.label))
  else
    log.error ('Failed to initialize device', device.label)
  end

end


-- Scheduled re-discover retry routine for unfound devices (stored in unfoundlist table)
-- We'll do a broader search here with 'ssdp:all' in case some badly behaved devices don't respond to specific uuid search target
local function proc_rediscover()

  if next(unfoundlist) ~= nil then
  
    log.debug ('Running periodic re-discovery process for uninitialized devices:')
    for device_network_id, table in pairs(unfoundlist) do
      log.debug (string.format('\t%s (%s)', device_network_id:match('([^#]+)##'), table.device.label))
    end
  
    upnp.discover(TARGETDEVICESEARCH, 3,    
                    function (upnpdev)
      
                      for device_network_id, table in pairs(unfoundlist) do
                        
                        if device_network_id:match('([^#]+)##') == upnpdev.uuid then
                        
                          local device = table.device
                          local callback = table.callback
                          
                          log.info (string.format('Known device <%s (%s)> re-discovered at %s', device.id, device.label, upnpdev.ip))
                          
                          unfoundlist[device_network_id] = nil
                          callback(device, upnpdev)
                        end
                      end
                    end,
                  false,
                  false
    )
  
     -- give discovery some time to finish
    socket.sleep(20)
    -- Reschedule this routine again if still unfound devices
    if next(unfoundlist) ~= nil then
      rediscover_timer = rediscovery_thread:call_with_delay(40, proc_rediscover, 're-discover routine')
    else
      rediscovery_thread:close()
    end
  end
end


local function schedule_rediscover(device, delay)
  
  if next(unfoundlist) == nil then
    unfoundlist[device.device_network_id] = { ['device'] = device, ['callback'] = startup_device }
    log.warn ('\tScheduling re-discover routine for later')
    if not rediscovery_thread then
      rediscovery_thread = Thread.Thread(upnpDriver, 'rediscover thread')
    end
    rediscover_timer = rediscovery_thread:call_with_delay(delay, proc_rediscover, 're-discover routine')
  else
    unfoundlist[device.device_network_id] = { ['device'] = device, ['callback'] = startup_device }
  end

end

------------------------------------------------------------------------
--                      CAPABILITY HANDLERS
------------------------------------------------------------------------

local function handle_refresh(driver, device, command)

  log.info ('Refresh requested')

  init_device(device)
    
end


local function handle_switch(driver, device, command)

  log.debug (string.format('%s switch turned %s / %s', command.component, command.command, command.args.value))
  
  local cam_func = device:get_field('onvif_func')
  
  if cam_func then
    if cam_func.motion_events == true then
    
      if command.args.value == 'On' then
        if events.subscribe(driver, device, cam_func.motion_event_name, event_handler) then
          device:emit_event(cap_motion.switch('On'))
          return
        end
      elseif command.args.value == 'Off' then
        events.shutdownserver(driver, device)
      end
    else
      log.debug('Motion events not available for', device.label)
    end
  else
    log.warn(string.format('Cannot enable motion events - %s not yet initialized', device.label))
  end
  
  device:emit_event(cap_motion.switch('Off'))
  
end


local function handle_stream(driver, device, command)

  log.debug('Streaming handler invoked with command', command.command)
  
  local live_video = {
     ['InHomeURL'] = '',
     ['OutHomeURL'] = ''
  }
  
  local cam_func = device:get_field('onvif_func')
  
  if cam_func then
  
    if command.command == 'startStream' then
    
      if cam_func.stream_uri then
      
        local build_url = 'rtsp://' .. device.preferences.userid .. ':' .. device.preferences.password .. '@' .. cam_func.stream_uri:match('//(.+)') 
        log.debug ('Stream URL for SmartThings:', build_url)
        live_video.InHomeURL = build_url
        --live_video.OutHomeURL = build_url
      end
    
    end
    
    device:emit_event(capabilities.videoStream.stream(live_video))
    
  end

end
  
------------------------------------------------------------------------
--                    DRIVER LIFECYCLE HANDLERS
------------------------------------------------------------------------

-- Lifecycle handler to initialize existing devices AND newly discovered devices
local function device_init(driver, device)
  
  log.debug(string.format("INIT handler for: <%s (%s)>", device.device_network_id, device.label))

  init_device(device)
  
end


-- Called when device is initially discovered and created in SmartThings
local function device_added (driver, device)

  local urn = device.device_network_id

  log.info(string.format('ADDED handler: <%s (%s)> successfully added; device_network_id = %s', device.id, device.label, device.device_network_id))
  
  -- get UPnP metadata that was squirreled away when device was created
  local ipcam = newly_added[urn]
  
  if ipcam ~= nil then
    
    device:set_field('onvif_disco', ipcam, {['persist'] = true })
    
    newly_added[urn] = nil                                               -- we're done with it
    
    device:emit_event(capabilities.motionSensor.motion('inactive'))
    device:emit_event(cap_motion.switch('Off'))
    
    device:emit_component_event(device.profile.components.info, cap_status.status('Not configured'))

  else
    log.error ('IPCam meta data not found for new device')               -- this should never happen!
  end

  log.debug ('ADDED handler exiting for ' .. device.label)
  
  disco_sem:release()         -- allow next device to be created

end

-- Called when SmartThings thinks the device needs provisioning
local function device_doconfigure (_, device)

  -- Nothing to do here!

end


-- Called when device was deleted via mobile app
local function device_removed(driver, device)
  
  log.info("<" .. device.id .. "> removed")
  
  events.shutdownserver(driver, device)
  
  local device_list = driver:get_devices()
  
  if #device_list == 0 then
    log.warn ('No more devices')
  end  
end


local function handler_infochanged(driver, device, event, args)

  log.debug ('INFOCHANGED handler; event=', event)
  
  if args.old_st_store.preferences then
  
    if args.old_st_store.preferences.userid ~= device.preferences.userid then 
      log.info ('UserID updated to', device.preferences.userid)
      if device.preferences.userid ~= '*****' then
        device:emit_component_event(device.profile.components.info, cap_status.status('Tap Refresh to connect'))
      end
    elseif args.old_st_store.preferences.password ~= device.preferences.password then 
      log.info ('Password updated to', device.preferences.password)
      if device.preferences.userid ~= '*****' then
        device:emit_component_event(device.profile.components.info, cap_status.status('Tap Refresh to connect'))
      end
    elseif args.old_st_store.preferences.autorevert ~= device.preferences.autovert then 
      log.info ('Motion auto-revert updated to', device.preferences.autorevert)
    elseif args.old_st_store.preferences.revertdelay ~= device.preferences.revertdelay then 
      log.info ('Motion auto-revert delay updated to', device.preferences.revertdelay)
    else
      -- Assume driver is restarting - shutdown everything
      log.debug ('****** DRIVER RESTART ASSUMED ******')
    end
    
  end
end


-- If the hub's IP address changes, this handler is called
local function lan_info_changed_handler(driver, hub_ipv4)
  if driver.listen_ip == nil or hub_ipv4 ~= driver.listen_ip then
    log.info("Hub IP address has changed, restarting eventing server and resubscribing")
    
    upnp.reset(driver)                                                  -- reset device monitor and subscription event server
    resubscribe_all(driver)
  end
end


-- Perform WS discovery to find target device(s) on the LAN
local function discovery_handler(driver, _, should_continue)
  log.debug("Starting discovery")
  
  local known_devices = {}
  local found_devices = {}

  local device_list = driver:get_devices()
  for _, device in ipairs(device_list) do
    known_devices[device.device_network_id] = true
  end

  local waittime = 20

  -- We'll limit our discovery to repeat_count to minimize unnecessary LAN traffic

  while should_continue() do
    log.debug('Making WS discovery request')
    
    --****************************************************************************
    discover.discover(waittime,    
                  function (ipcam)
    
                    local urn = ipcam.urn
                    local ip = ipcam.ip

                    if not known_devices[urn] and not found_devices[urn] then
                      found_devices[urn] = true

                      local modelname = 'Unknown'
                      local name = 'IPCam #' .. tostring(discovered_num) .. ' (configure!)'
                      discovered_num = discovered_num + 1
                      local manufacturer = 'Unknown'
                      
                      local vendlabel
                      if ipcam.vendname then
                        vendlabel = ipcam.vendname
                      else
                        vendlabel = name
                      end
                      
                      local devprofile = 'onvif_cam.v1'

                      local create_device_msg = {
                        type = "LAN",
                        
                        device_network_id = urn,
                        label = name,
                        profile = devprofile,
                        manufacturer = manufacturer,
                        model = modelname,
                        vendor_provided_label = vendlabel,
                      }
                      
                      newly_added[urn] = ipcam          -- squirrel away device metadata for device_added handler
                                                          -- ... because there's currently no way to attach it to the new device here :-(
                                                          
                      -- Device creation protected by a semaphore,
                      --   since rapid sequential creation calls causes problems with Edge right now.
                      --   Semaphore is released at the end of ADDED lifecycle.
                      disco_sem:acquire(function()  
                        log.info(string.format('Creating discovered IP Camera found at %s', ip))
                        log.info("\tdevice_network_id = " .. urn)
                        assert (
                          driver:try_create_device(create_device_msg),
                          "failed to create device record"
                        )
                      end)

                    else
                      log.debug("Discovered device was already known")
                    end
                  end,
                  false
    )
    --***************************************************************************
    
  end
  log.info("Driver is exiting discovery")
end

-----------------------------------------------------------------------
--        DRIVER MAINLINE: Build driver context table
-----------------------------------------------------------------------
onvifDriver = Driver("onvifDriver", {
  discovery = discovery_handler,
  lifecycle_handlers = {
    init = device_init,
    added = device_added,
    infoChanged = handler_infochanged,
    doConfigure = device_doconfigure,
    deleted = device_removed,
    removed = device_removed,
  },
  lan_info_changed_handler = lan_info_changed_handler,
  capability_handlers = {
  
    [cap_refresh.ID] = {
      [cap_refresh.commands.push.NAME] = handle_refresh,
    },
    [cap_motion.ID] = {
      [cap_motion.commands.setSwitch.NAME] = handle_switch,
    },
    [capabilities.videoStream.ID] = {
      [capabilities.videoStream.commands.startStream.NAME] = handle_stream,
      [capabilities.videoStream.commands.stopStream.NAME] = handle_stream,
    },
  }
})

log.debug("**** ONVIF Driver V1 Start ****")

disco_sem = Semaphore()

onvifDriver:run()

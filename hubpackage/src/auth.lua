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
  
  ONVIF Driver authorization-related routines


--]]


local cosock = require "cosock"
local socket = require "cosock.socket"
local log = require "log"

local base64 = require "base64"
local sha1 = require "sha1"
local md5 = require "md5"

local client_nonce = {}
local WSUSERNAMETOKEN_NONCE_LEN = 22
local HTTPDIGEST_CNONCE_LEN = 4
local MAX_NONCE_LIFE = 300    -- in seconds


local function refresh_client_nonce(nonce_len)

  local client_nonce = {}
  local binary_nonce = ''
      
  for byte = 1, nonce_len do
  
    local num = math.random(0,255)
    binary_nonce = binary_nonce .. string.char(num)
    
  end
  
  client_nonce.binary = binary_nonce
  client_nonce.base64 = base64.encode(binary_nonce)
  client_nonce.hex = ''
  
  for i=1, #binary_nonce do
    client_nonce.hex = client_nonce.hex .. string.format('%02x', binary_nonce:byte(i))
  end
  
  local hub_datetime = os.date("!*t")
  client_nonce.epochtime = socket.gettime()
  local created = string.format('%02d-%02d-%02dT%02d:%02d:%02d.000Z',hub_datetime.year,hub_datetime.month,hub_datetime.day,hub_datetime.hour,hub_datetime.min,hub_datetime.sec)
  client_nonce.created = created

  return client_nonce

end

local function get_client_nonce(device, length, authtype)

  if authtype == 'http' then

    local client_nonce = device:get_field('onvif_cnonce')
    
    if client_nonce then

      if (socket.gettime() - client_nonce.epochtime) <= MAX_NONCE_LIFE then
        return client_nonce
      end
    end
  end
    
  client_nonce = refresh_client_nonce(length)
  device:set_field('onvif_cnonce', client_nonce)
  return client_nonce
    
end


-- Create Security Header XML for WS Security Username token

local function build_UsernameToken(device)

  local userid = device.preferences.userid
  local password = device.preferences.password
  
  local client_nonce = get_client_nonce(device, WSUSERNAMETOKEN_NONCE_LEN, 'wss')

  local base64_digest = base64.encode(sha1.binary(client_nonce.binary .. client_nonce.created .. password))
  
  local UsernameToken = 
    '      <UsernameToken><Username>' .. userid .. '</Username>' ..
    '<Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">' ..
    base64_digest .. '</Password>' ..
    '<Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">' ..
    client_nonce.base64 ..'</Nonce>' ..
    '<Created xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">' ..
    client_nonce.created .. '</Created></UsernameToken>\n'
    
  local SecurityHeader_p1 = [[
    <Security s:mustUnderstand="1" xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
]]

  local SecurityHeader_p2 = [[
    </Security>
]]

  local authinfo = {}
  authinfo.type = 'wss'
  device:set_field('onvif_authinfo', authinfo)
  
  local security_header = SecurityHeader_p1 .. UsernameToken .. SecurityHeader_p2
  --log.debug ('wss authorization created:')
  --log.debug (security_header)
  
  return security_header

end


-- Create HTTP Header for HTTP Authorizations 

local function build_authheader(device, method, fullurl, authdata)

  -- Example authdata:
  --   'Digest qop="auth", realm="IP Camera(C2053)", nonce="4e47597a596d59314f4449364d7a4e694e5445354e32553d", stale=FALSE, algorithm=MD5'

  
  if authdata.type == 'Digest' then
  
    if authdata.algorithm then
      if string.lower(authdata.algorithm) ~= 'md5' then
        log.error ('Unsupported authentation algorithm:', authdata.algorithm)
        return
      end
    end

    local uri = fullurl:match('http://[^/]+(.+)')
    
    local userid = device.preferences.userid
    local password = device.preferences.password
    
    local authinfo = device:get_field('onvif_authinfo')
    
    if not authinfo then
      authinfo = {}
      if authdata.qop then
        authinfo.nonce_count = 1
      end
    else
      if authdata.qop then
        if authdata.nonce == authinfo.priornonce then
          authinfo.nonce_count = authinfo.nonce_count + 1
        else
          authinfo.nonce_count = 1
        end
      end
    end  
      
    local ha1 = md5.sumhexa(userid .. ':' .. authdata.realm .. ':' .. password)
    local ha2 = md5.sumhexa(method .. ':' .. uri)
    
    local response
    local cnonce, h_nonce_count
    
    if authdata.qop then
      cnonce = get_client_nonce(device, HTTPDIGEST_CNONCE_LEN, 'http')
      h_nonce_count = string.format('%08x', authinfo.nonce_count)
      authinfo.priornonce = authdata.nonce
      response = md5.sumhexa(ha1 .. ':' .. authdata.nonce .. ':' .. h_nonce_count .. ':' .. cnonce.hex .. ':' .. authdata.qop .. ':' .. ha2)
    else
      response = md5.sumhexa(ha1 .. ':' .. authdata.nonce .. ':' .. ha2)
    end
    
    -- Initialize optional HTTP Authorization header fields
    
    local opaque = ''
    local qop = ''
    local algorithm = ''
    local clientnonce = ''
    local nc = ''
    
    if authdata.opaque then
      opaque = ', opaque="' .. authdata.opaque .. '"'
    end
    
    if authdata.qop then
      qop = ', qop=' .. authdata.qop .. ', '
      clientnonce = 'cnonce="' .. cnonce.hex .. '", '
      nc = 'nc=' .. h_nonce_count
    end
    
    if authdata.algorithm then
      algorithm = 'algorithm=MD5, '
    end
    
    local authheader =  'Digest ' .. 
                        'username="' .. userid .. '", ' ..
                        'realm="' .. authdata.realm .. '", ' ..
                        algorithm ..
                        'nonce="' .. authdata.nonce .. '", ' ..
                        'uri="' .. uri .. '", ' ..
                        'response="' .. response .. '"' ..
                        opaque ..
                        qop ..
                        clientnonce ..
                        nc 
    
    --log.debug ('Constructed auth header:', authheader)
    
    authinfo.type = 'http'
    authinfo.authdata = authdata
    authinfo.authheader = authheader
    device:set_field('onvif_authinfo', authinfo)
    
    return authheader
    
  else
    log.error ('Unsupported authorization type:', authtype)
  end

end


return {
          gen_nonce = gen_nonce,
          build_UsernameToken = build_UsernameToken,
          build_authheader = build_authheader
}

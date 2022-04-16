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
local CLIENT_NONCE_LEN = 22
local MAX_NONCE_LIFE = 300    -- in seconds


local function refresh_client_nonce()

  local binary_nonce = ''
      
  for byte = 1, CLIENT_NONCE_LEN do
  
    local num = math.random(0,255)
    binary_nonce = binary_nonce .. string.char(num)
    
  end
  
  client_nonce.binary = binary_nonce
  client_nonce.base64 = base64.encode(binary_nonce)
  
  local hub_datetime = os.date("!*t")
  client_nonce.epochtime = socket.gettime()
  local created = string.format('%02d-%02d-%02dT%02d:%02d:%02d.000Z',hub_datetime.year,hub_datetime.month,hub_datetime.day,hub_datetime.hour,hub_datetime.min,hub_datetime.sec)
  client_nonce.created = created

  return client_nonce

end

local function get_client_nonce()

  if client_nonce.binary then
  
    if (socket.gettime() - client_nonce.epochtime) <= MAX_NONCE_LIFE then
      return client_nonce
    end
  end
    
  return refresh_client_nonce()
    
end


local function build_UsernameToken(userid, password)

  local client_nonce = get_client_nonce()

  local base64_digest = base64.encode(sha1.binary(client_nonce.binary .. client_nonce.created .. password))
  
  local UsernameToken = 
    '<UsernameToken><Username>' .. userid .. '</Username>' ..
    '<Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">' ..
    base64_digest .. '</Password>' ..
    '<Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">' ..
    client_nonce.base64 ..'</Nonce>' ..
    '<Created xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">' ..
    client_nonce.created .. '</Created></UsernameToken>'
  
  return UsernameToken

end

return {
          gen_nonce = gen_nonce,
          build_UsernameToken = build_UsernameToken,
}

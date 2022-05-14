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
  
  ONVIF Driver common routines


--]]


local xml2lua = require "xml2lua"
local xml_handler = require "xmlhandler.tree"
local log = require "log"


local function xml_to_table(data)

  if string.find(data,'<?xml version=\"1.0\"') then
	
    local handler = xml_handler:new()
    local xml_parser = xml2lua.parser(handler)

    xml_parser:parse(data)

    if not handler.root then
	    log.error ("Could not parse XML")
	    return nil, nil
    end
    
    return handler.root

  else
    log.warn ('Not an XML response')
  end

end


local function is_element(xml, element_list)

  local xtable = xml
  local itemcount = #element_list
  local foundcount = 0
  
  for i, element in ipairs(element_list) do
    xtable = xtable[element]
    if xtable then
      foundcount = foundcount + 1
    else
      break
    end
  end
	  
  if foundcount == itemcount then
    return true
  else
    return false
  end

end

local function _strip_xmlns(xml, newtable)

  for key, value in pairs(xml) do
    local newkey
    if type(key) == 'number' then
      newkey = key
    else
      newkey = key:match(':(.+)')
      if not newkey then
	newkey = key
      end
    end
    if (type(value) == 'table') then
      newtable[newkey] = {}
      _strip_xmlns(value, newtable[newkey])
    else
      newtable[newkey] = value
    end
  end
  
end

local function strip_xmlns(xml)

  local stripped = {}
  
  _strip_xmlns(xml, stripped)
  
  return stripped
	
end

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


local function hextoint(hexstring)

  local hexconv = {
		    ['0'] = 0,
		    ['1'] = 1,
		    ['2'] = 2,
		    ['3'] = 3,
		    ['4'] = 4,
		    ['5'] = 5,
		    ['6'] = 6, 
		    ['7'] = 7,
		    ['8'] = 8,
		    ['9'] = 9,
		    ['a'] = 10,
		    ['b'] = 11,
		    ['c'] = 12,
		    ['d'] = 13,
		    ['e'] = 14,
		    ['f'] = 15,
		  }

  local intnum = 0

  for i = 1, #hexstring, 2 do
    local val = (hexconv[string.sub(hexstring, i, i)] * 16) + hexconv[string.sub(hexstring, i+1, i+1)]
    intnum = intnum + val
  end
  
  return intnum

end


return {
	  xml_to_table = xml_to_table,
	  is_element = is_element,
	  strip_xmlns = strip_xmlns,
	  compact_XML = compact_XML,
          disptable = disptable,
	  hextoint = hextoint,
}

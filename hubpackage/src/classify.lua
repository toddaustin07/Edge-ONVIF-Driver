
--[[
Credit:  Ross Tyler
Support for the Object-Oriented Programming concepts discussed here
https://www.lua.org/pil/contents.html#16
]]--

-- new implements the __call metamethod of a class.
-- it creates an empty object ({})
-- assigns class as the metatable for this object,
-- and initializes it (calls the class:_init method).
-- the object is returned.
local function new(class, ...)
    local self = setmetatable({}, class)
    class:_init(self, ...)
    return self
end

-- join implements the __index metamethod of a multiple-inheritance class as a function
-- (instead of a table, as in single-inheritance).
-- indexing with a nil key will return the ordered list of super classes;
-- otherwise, the __index metamethods of the super classes are joined
-- by finding the first that resolves a key and caching the result in the class.
local function join(_supers)
    return function(class, key)
        if nil == key then
            return _supers
        end
        for _, _super in ipairs(_supers) do
            local value = _super[key]
            if nil ~= value then
                class[key] = value
                return value
            end
        end
    end
end

-- super returns the super class of a class.
-- for a single-inheritance class, this is the table of super class.
-- for a multiple-inheritance class, this is the function that joins the super class tables.
local function super(class)
    return getmetatable(class).__index
end

-- supers returns an iterator over the super classes of a multiple-inheritance class
local function supers(class)
    return coroutine.wrap(function()
        for _, _super in ipairs(super(class)()) do
            coroutine.yield(_super)
        end
    end)
end

return {
    super = super,

    supers = supers,

    -- return the class of an object
    class = function(self)
        return getmetatable(self)
    end,

    -- adapt class to implement single-inheritance from an optional super_class.
    -- return the adaptation.
    single = function(class, super_class)
        class.__index = class
        setmetatable(class, {
            __index = super_class,
            __call = new
        })
        return class
    end,

    -- adapt class to implement multiple-inheritance from an ordered list of super classes
    -- return the adaptation.
    multiple = function(class, ...)
        class.__index = class
        setmetatable(class, {
            __index = join{...},
            __call = new
        })
        return class
    end,

    -- adapt class so that a construction of an object of this class
    -- raises an error of this class type.
    -- return the adaptation.
    error = function(class)
        class.__index = class
        setmetatable(class, {
            __call = function(_class, ...)
                error(setmetatable({...}, _class))
            end
        })
        return class
    end,
}

-- Credit:  Ross Tyler
local classify = require "classify"

-- https://en.wikipedia.org/wiki/Semaphore_(programming)
-- borrowing Java operation names (acquire and release).
return classify.single({
    _init = function(class, self, permits)
        self._permits = permits or 1
        self._pending = {}
    end,

    acquire = function(self, use)
        self._permits = self._permits - 1
        if 0 > self._permits then
            -- use of resource is pending a future release
            table.insert(self._pending, use)
        else
            -- use of resource is permitted now
            use()
        end
    end,

    release = function(self)
        self._permits = self._permits + 1
        if 0 < #self._pending then
            -- allow the first pending to use the resource
            table.remove(self._pending, 1)()
        end
    end,
})

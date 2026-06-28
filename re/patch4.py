#!/usr/bin/env python3
# Detour LAB_141000650 (token-decrypt "get key" callback: key = *r8 + 0x5f0).
# Capture the 32-byte key at object+0x5f0 into a new RWX section. Relocate the
# first 9 bytes: mov rax,[r8] (3) + add rax,0x5f0 (6). Jmp back to 0x141000659.
import struct
SRC="/mnt/games/Enshrouded.v0.9.1.2/Enshrouded/enshrouded.exe.preexfil"
OUT="/mnt/games/Enshrouded.v0.9.1.2/Enshrouded/enshrouded.exe"
FN_RVA=0x1000650; JMPBACK=0x1000659
RELOC=b"\x49\x8b\x00\x48\x05\xf0\x05\x00\x00"     # mov rax,[r8]; add rax,0x5f0

data=bytearray(open(SRC,"rb").read())
pe=struct.unpack_from("<I",data,0x3c)[0]; nsec=struct.unpack_from("<H",data,pe+6)[0]
opt=pe+24; sohdr=struct.unpack_from("<H",data,pe+20)[0]
fa=struct.unpack_from("<I",data,opt+36)[0]; sa=struct.unpack_from("<I",data,opt+32)[0]
sectbl=opt+sohdr; maxva=0
for i in range(nsec):
    o=sectbl+i*40; maxva=max(maxva,struct.unpack_from("<I",data,o+12)[0]+struct.unpack_from("<I",data,o+8)[0])
al=lambda x,a:(x+a-1)&~(a-1)
new_rva=al(maxva,sa); new_foff=al(len(data),fa); stub_rva=new_rva; BUF=new_rva+0x200

def build():
    b=bytearray()
    def lea(dst):
        nonlocal b; pos=stub_rva+len(b); b+=b"\x48\x8d\x3d"+struct.pack("<i",dst-(pos+7))
    b+=b"\x50\x56\x57"                       # push rax,rsi,rdi
    b+=b"\x49\x8b\x30"                        # mov rsi,[r8]   (object)
    b+=b"\x48\x81\xc6\xf0\x05\x00\x00"        # add rsi,0x5f0  (key ptr)
    lea(BUF)                                  # lea rdi,[BUF]
    for off in (0,8,0x10,0x18):              # copy 32 bytes
        b+=b"\x48\x8b\x46"+bytes([off])+b"\x48\x89\x47"+bytes([off])
    b+=b"\xc6\x47\x20\x01"                    # mov byte [rdi+0x20],1 (flag)
    b+=b"\x5f\x5e\x58"                        # pop rdi,rsi,rax
    b+=RELOC
    jp=stub_rva+len(b); b+=b"\xe9"+struct.pack("<i",JMPBACK-(jp+5))
    return bytes(b)

stub=build(); raw=bytearray(0x1000); raw[:len(stub)]=stub
first=min(struct.unpack_from("<I",data,sectbl+i*40+20)[0] for i in range(nsec))
ho=sectbl+nsec*40; assert ho+40<=first
data[ho:ho+8]=b".keenx\0\0"
struct.pack_into("<I",data,ho+8,0x1000); struct.pack_into("<I",data,ho+12,new_rva)
struct.pack_into("<I",data,ho+16,0x1000); struct.pack_into("<I",data,ho+20,new_foff)
struct.pack_into("<I",data,ho+36,0xE0000020)
struct.pack_into("<H",data,pe+6,nsec+1); struct.pack_into("<I",data,opt+56,al(new_rva+0x1000,sa))
if len(data)<new_foff: data.extend(b"\0"*(new_foff-len(data)))
data[new_foff:new_foff+0x1000]=raw
foff=0x400+(FN_RVA-0x1000)
data[foff:foff+9]=b"\xe9"+struct.pack("<i",stub_rva-(FN_RVA+5))+b"\x90\x90\x90\x90"
open(OUT,"wb").write(data)
print(f"patched. stub={stub_rva:#x} BUF={BUF:#x} ({len(stub)}B)  runtime key buffer=base+{BUF:#x} (32B key, flag@+0x20)")

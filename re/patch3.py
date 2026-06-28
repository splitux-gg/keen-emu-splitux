#!/usr/bin/env python3
# Detour FUN_140ffda50 (the crypto-core that logs the token's "session key
# decryption failed"). Capture per call: callback p6, key-ptr p4(r9), nonce p8(24B).
# Ring in a new RWX section. Win64 args at entry: rcx,rdx,r8,r9=p1-4;
# [rsp+0x28]=p5 [rsp+0x30]=p6 [rsp+0x38]=p7 [rsp+0x40]=p8.
import struct
SRC="/mnt/games/Enshrouded.v0.9.1.2/Enshrouded/enshrouded.exe.preexfil"
OUT="/mnt/games/Enshrouded.v0.9.1.2/Enshrouded/enshrouded.exe"
FN_RVA=0xffda50; JMPBACK=0xffda55
RELOC=b"\x48\x89\x5c\x24\x08"            # mov [rsp+8],rbx (5 bytes)

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
    b+=b"\x50\x51\x56\x57"                 # push rax,rcx,rsi,rdi (0x20)
    lea(BUF); b+=b"\x8b\x07\x83\xf8\x10"   # lea rdi,[BUF]; mov eax,[rdi]; cmp eax,16
    jae=len(b); b+=b"\x73\x00"
    b+=b"\x6b\xc8\x28"                     # imul ecx,eax,40
    b+=b"\x48\x8d\x7c\x0f\x04"             # lea rdi,[rdi+rcx+4]
    b+=b"\x48\x8b\x44\x24\x50\x48\x89\x07"         # mov rax,[rsp+0x50](p6); mov [rdi],rax
    b+=b"\x4c\x89\x4f\x08"                         # mov [rdi+8],r9   (p4 key)
    b+=b"\x48\x8b\x74\x24\x60"                     # mov rsi,[rsp+0x60] (p8 nonce ptr)
    b+=b"\x48\x85\xf6"                             # test rsi,rsi
    nz=len(b); b+=b"\x74\x00"                      # jz nodref
    b+=b"\x48\x8b\x06\x48\x89\x47\x10"             # mov rax,[rsi];     mov [rdi+0x10],rax
    b+=b"\x48\x8b\x46\x08\x48\x89\x47\x18"         # mov rax,[rsi+8];   mov [rdi+0x18],rax
    b+=b"\x48\x8b\x46\x10\x48\x89\x47\x20"         # mov rax,[rsi+0x10];mov [rdi+0x20],rax
    b[nz+1]=len(b)-(nz+2)                          # patch jz nodref
    lea(BUF); b+=b"\xff\x07"                       # lea rdi,[BUF]; inc dword[rdi]
    skip=len(b); b[jae+1]=skip-(jae+2)
    b+=b"\x5f\x5e\x59\x58"                         # pop rdi,rsi,rcx,rax
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
data[foff:foff+5]=b"\xe9"+struct.pack("<i",stub_rva-(FN_RVA+5))
open(OUT,"wb").write(data)
print(f"patched FUN_140ffda50. stub={stub_rva:#x} BUF={BUF:#x} ({len(stub)}B)")
print(f"runtime ring=base+{BUF:#x}  ([u32 count][40B: p6@+0, keyptr@+8, nonce24@+0x10])")

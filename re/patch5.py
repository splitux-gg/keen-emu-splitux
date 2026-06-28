#!/usr/bin/env python3
# Detour FUN_1405d5490(out=rcx,in=rdx,inlen=r8,nonce=r9,key=[rsp+0x28]).
# Capture EVERY call (ring): in_first16, nonce24, key32. Read via /proc.
import struct
SRC="/mnt/games/Enshrouded.v0.9.1.2/Enshrouded/enshrouded.exe.preexfil"
OUT="/mnt/games/Enshrouded.v0.9.1.2/Enshrouded/enshrouded.exe"
FN_RVA=0x5d5490; JMPBACK=0x5d5497
RELOC=b"\x48\x83\xec\x38\x4d\x89\xcb"   # sub rsp,0x38 ; mov r11,r9
ESZ=72                                  # entry: in16 @0, nonce24 @16, key32 @40

data=bytearray(open(SRC,"rb").read())
pe=struct.unpack_from("<I",data,0x3c)[0]; nsec=struct.unpack_from("<H",data,pe+6)[0]
opt=pe+24; sohdr=struct.unpack_from("<H",data,pe+20)[0]
fa=struct.unpack_from("<I",data,opt+36)[0]; sa=struct.unpack_from("<I",data,opt+32)[0]
sectbl=opt+sohdr; maxva=0
for i in range(nsec):
    o=sectbl+i*40; maxva=max(maxva,struct.unpack_from("<I",data,o+12)[0]+struct.unpack_from("<I",data,o+8)[0])
al=lambda x,a:(x+a-1)&~(a-1)
new_rva=al(maxva,sa); new_foff=al(len(data),fa); stub_rva=new_rva; BUF=new_rva+0x300

def build():
    b=bytearray()
    def lea(dst):
        nonlocal b; pos=stub_rva+len(b); b+=b"\x48\x8d\x3d"+struct.pack("<i",dst-(pos+7))
    def cp(srcreg_load, n, dstoff):   # copy n*8 bytes [rsi]->[rdi+dstoff]
        nonlocal b
        for k in range(n):
            b+=b"\x48\x8b\x46"+bytes([k*8])            # mov rax,[rsi+k*8]
            b+=b"\x48\x89\x47"+bytes([dstoff+k*8])     # mov [rdi+dstoff+k*8],rax
    b+=b"\x50\x51\x56\x57"                      # push rax,rcx,rsi,rdi (0x20)
    lea(BUF); b+=b"\x8b\x07\x83\xf8\x0c"        # mov eax,[rdi](cnt); cmp eax,12
    jae=len(b); b+=b"\x73\x00"
    b+=b"\x6b\xc8"+bytes([ESZ])                 # imul ecx,eax,ESZ
    b+=b"\x48\x8d\x7c\x0f\x04"                  # lea rdi,[rdi+rcx+4]  (slot)
    b+=b"\x48\x89\xd6"; cp(0,2,0)               # mov rsi,rdx(in); copy in[0:16] @0
    b+=b"\x4c\x89\xce"; cp(0,3,16)              # mov rsi,r9(nonce); copy nonce[0:24] @16
    b+=b"\x48\x8b\x74\x24\x48"; cp(0,4,40)      # mov rsi,[rsp+0x48](key ptr; 4push=0x20,+0x28); copy 32 @40
    lea(BUF); b+=b"\xff\x07"                    # inc dword[BUF]
    skip=len(b); b[jae+1]=skip-(jae+2)
    b+=b"\x5f\x5e\x59\x58"+RELOC
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
data[foff:foff+7]=b"\xe9"+struct.pack("<i",stub_rva-(FN_RVA+5))+b"\x90\x90"
open(OUT,"wb").write(data)
print(f"patched. stub={stub_rva:#x} BUF={BUF:#x} ({len(stub)}B) runtime ring=base+{BUF:#x} (in16|nonce24|key32, {ESZ}B each)")

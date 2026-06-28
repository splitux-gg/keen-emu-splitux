#!/usr/bin/env python3
# Keen reflection (KNF) schema dumper for enshrouded.exe.
# Type descriptor layout (RE'd from FUN_140fa4e90):
#   +0x00 name_ptr   +0x08 struct_size   +0x10 field_array_ptr   +0x18 field_count
# Field record = 0x40 bytes:
#   +0x00 name_ptr   +0x08 type_tag(u32)  +0x0c elem_tag(u32)
#   +0x18 size       +0x20 offset         +0x38 subdesc_ptr (composite types)
import sys, struct

EXE = "/mnt/games/Enshrouded.v0.9.1.2/Enshrouded/enshrouded.exe.preexfil"
data = open(EXE, "rb").read()

# --- minimal PE parse: vaddr -> file offset ---
pe = struct.unpack_from("<I", data, 0x3c)[0]
assert data[pe:pe+4] == b"PE\0\0"
nsec = struct.unpack_from("<H", data, pe+6)[0]
opt = pe + 24
imagebase = struct.unpack_from("<Q", data, opt+24)[0]
opt_size = struct.unpack_from("<H", data, pe+20)[0]
sect = opt + opt_size
secs = []
for i in range(nsec):
    off = sect + i*40
    va = struct.unpack_from("<I", data, off+12)[0]
    vs = struct.unpack_from("<I", data, off+8)[0]
    raw = struct.unpack_from("<I", data, off+20)[0]
    secs.append((va, vs, raw))

def off_of(vaddr):
    rva = vaddr - imagebase
    for va, vs, raw in secs:
        if va <= rva < va + vs:
            return raw + (rva - va)
    return None

def cstr(vaddr):
    o = off_of(vaddr)
    if o is None: return f"<?{vaddr:#x}>"
    end = data.index(b"\0", o)
    return data[o:end].decode("latin1")

def u64(vaddr):
    o = off_of(vaddr)
    return struct.unpack_from("<Q", data, o)[0] if o is not None else 0
def u32(vaddr):
    o = off_of(vaddr)
    return struct.unpack_from("<I", data, o)[0] if o is not None else 0

# KNF wire types (from FUN_140fa4e90 switch on field+0x08):
WIRE = {0:"bool(1b)", 1:"u32", 7:"u32", 8:"u32", 3:"u8", 4:"u8", 5:"u16", 6:"u16",
        9:"u64", 10:"u64", 0xb:"cstring", 0xc:"struct", 0xd:"enum"}
KIND = {0:"scalar", 1:"array", 2:"varray"}

def dump(desc_vaddr, indent=0, seen=None):
    if seen is None: seen = set()
    pad = "    " * indent
    name = cstr(u64(desc_vaddr))
    cnt  = u64(desc_vaddr+0x18)
    farr = u64(desc_vaddr+0x10)
    if cnt > 64 or off_of(farr) is None:   # enum / opaque descriptor (different layout)
        print(f"{pad}{name}  (enum/opaque)"); return
    print(f"{pad}{name}  ({cnt} fields)")
    if desc_vaddr in seen:
        print(f"{pad}  (recursion)"); return
    seen = seen | {desc_vaddr}
    for i in range(cnt):
        r = farr + i*0x40
        fname = cstr(u64(r))
        wt    = u32(r+8)
        kind  = u32(r+0x10)
        count = u64(r+0x28)
        ebits = u64(r+0x30)
        sub   = u64(r+0x38)
        wn = WIRE.get(wt, f"wt{wt}")
        arr = "(opt)" if kind == 0 else (f"[{count}]" if kind == 1 else f"[max {count}]")
        if wt == 0xc and sub:                      # nested struct
            print(f"{pad}  {fname}: {cstr(u64(sub))}{arr}")
            dump(sub, indent+2, seen)
        elif wt == 0xd:                            # enum
            print(f"{pad}  {fname}: enum({ebits}b){arr}")
        else:
            print(f"{pad}  {fname}: {wn}{arr}")

for arg in (sys.argv[1:] or ["0x141edf750"]):
    dump(int(arg, 16))
    print()

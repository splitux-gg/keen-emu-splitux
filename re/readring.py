#!/usr/bin/env python3
# Read the patch5.py exfil ring from a running enshrouded.exe.
# Finds the runtime imagebase via the unique "eonlinedb..." rdata string,
# then dumps each FUN_1405d5490 call's captured (in16, nonce24, key32).
import sys, struct, re

PID = int(sys.argv[1])
BUF_RVA = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x2da7300
ESZ = 72

ANCHOR = b"eonlinedb.enshrouded.com:27503"
ANCHOR_VA = 0x141d00f98
IMAGEBASE = 0x140000000
ANCHOR_RVA = ANCHOR_VA - IMAGEBASE  # 0x1d00f98

mem = open(f"/proc/{PID}/mem", "rb", 0)

def read(addr, n):
    mem.seek(addr)
    return mem.read(n)

# parse maps: readable regions
regions = []
for line in open(f"/proc/{PID}/maps"):
    m = re.match(r"([0-9a-f]+)-([0-9a-f]+) (\S+)", line)
    if not m: continue
    perms = m.group(3)
    if perms[0] != 'r': continue
    a, b = int(m.group(1), 16), int(m.group(2), 16)
    if b - a > 0x40000000: continue  # skip huge reserved
    regions.append((a, b))

# find the anchor string
base = None
for a, b in regions:
    try:
        chunk = read(a, b - a)
    except Exception:
        continue
    idx = chunk.find(ANCHOR)
    if idx != -1:
        anchor_addr = a + idx
        base = anchor_addr - ANCHOR_RVA
        print(f"anchor @ {anchor_addr:#x} -> imagebase = {base:#x}")
        break

if base is None:
    print("anchor not found; dumping region list");
    for a,b in regions: print(f"  {a:#x}-{b:#x} ({(b-a)//1024}k)")
    sys.exit(1)

buf = base + BUF_RVA
count = struct.unpack_from("<I", read(buf, 4), 0)[0]
print(f"ring @ {buf:#x}  count={count}")
if count == 0 or count > 64:
    print("(no/invalid entries)"); sys.exit(0)

for i in range(min(count, 16)):
    e = read(buf + 4 + i*ESZ, ESZ)
    in16  = e[0:16]
    nonce = e[16:40]
    key   = e[40:72]
    print(f"--- call #{i} ---")
    print(f"  in16  = {in16.hex()}")
    print(f"  nonce = {nonce.hex()}")
    print(f"  key   = {key.hex()}")

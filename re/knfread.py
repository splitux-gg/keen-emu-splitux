#!/usr/bin/env python3
# KNF bitstream READER — validate against a captured decrypted LoginRequest.
import sys

REQ = bytes.fromhex(
 "000000000020"
 "2af051eee1d62afd6ce3b0347fe3079195057fe697e652151f05b9369460a3e9"  # 32B sessionKey?
 "031001482004602080e8a928e8000000040000002000000000000000a8000000"
 "00000000c800000010000002e9580000040040040000000000000000000000000000"
 "0002310101a833c16da80400000000000000000000000001a901023600149aa48eded8c8c4cae4cefcc8"
)

class BitReader:
    def __init__(self, data, bitpos=0):
        self.d = data; self.pos = bitpos
    def bits(self, n):
        v = 0
        for _ in range(n):
            byte = self.d[self.pos >> 3]
            bit = (byte >> (7 - (self.pos & 7))) & 1   # MSB-first
            v = (v << 1) | bit
            self.pos += 1
        return v
    def u8(self): return self.bits(8)
    def u16(self): return self.bits(16)
    def u32(self): return self.bits(32)
    def u64(self): return (self.bits(32) << 32) | self.bits(32)
    def varray(self):                # kind2: u16 len + bytes
        n = self.bits(16)
        return bytes(self.bits(8) for _ in range(n))

def parse(start_bits, enum_bits):
    print(f"\n=== parse @ bit {start_bits}, enum={enum_bits}b ===")
    r = BitReader(REQ, start_bits)
    try:
        sk   = r.varray();              print(f"  sessionKey   ({len(sk)}B) = {sk.hex()}")
        skid = r.bits(8);               print(f"  sessionKeyId = {skid}")
        tt   = r.bits(enum_bits);       print(f"  tokenType    = {tt}")
        tok  = r.varray();              print(f"  token        ({len(tok)}B) = {tok.hex()}")
        ts   = r.u64();                 print(f"  timestamp    = {ts}  ({ts:#x})")
        un   = r.varray();              print(f"  userName     ({len(un)}B) = {un!r}")
        st   = r.bits(enum_bits);       print(f"  serverType   = {st}")
        pp   = r.u16();                 print(f"  publicPort   = {pp}")
        pe   = r.varray();              print(f"  pubEncKey    ({len(pe)}B) = {pe.hex()}")
        ps   = r.varray();              print(f"  pubSigKey    ({len(ps)}B) = {ps.hex()}")
        print(f"  -> ended at bit {r.pos} / {len(REQ)*8}  (leftover {len(REQ)*8 - r.pos} bits)")
    except Exception as e:
        print(f"  parse error at bit {r.pos}: {e}")

print(f"total {len(REQ)} bytes")
for sb in (0, 32):
    for eb in (3, 8):
        parse(sb, eb)

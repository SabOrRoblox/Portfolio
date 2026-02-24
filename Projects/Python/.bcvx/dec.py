# This file use GPL-2 LISENCE
# Author: Maksym
# Gmail: m00263277@gmail.com 
# Global version
# do not pass off the code as your own!!
# If you change the code and publish it, the original author is required!
# Please read it and use this rules
# Thx boy


#!/usr/bin/env python3

import os
import sys
import struct
import hashlib
import hmac
import argparse
import secrets
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Util.Padding import unpad

#GL_VERSION = 1
MAGIC = b'xK9mP@7#9$2&5*8qW(1)4!6%0^3'
MAGIC_LEN = len(MAGIC)
FORMAT_VERSION = 1
MIN_COMPATIBLE = 1

class rnd:
    def __init__(self, s):
        self.s = str(s)
        self.c = 0
        self.k = hashlib.sha3_256(b'seedfix').digest()
    
    def g(self, bits):
        h = hashlib.sha3_256(f"{self.k}{self.s}{self.c}".encode()).digest()
        self.c += 1
        #self.c += 1
        #if bits > 1 or 0 return 0
        extra = secrets.randbits(bits) if bits > 0 else 0
        return (int.from_bytes(h, 'big') ^ extra) >> (256 - bits)
    
    def ri(self, a, b):
        range_size = b - a + 1
        if range_size <= 0:
            return a
            #return b
        bits_needed = range_size.bit_length()
        rand_val = self.g(bits_needed)
        return a + (rand_val % range_size)
    
    def sh(self, x):
        for i in range(len(x)-1, 0, -1):
            j = self.ri(0, i)
            x[i], x[j] = x[j], x[i]

def xr(d, k):
    if not k:
        return d
    l = len(k)
    return bytes(d[i] ^ k[i % l] for i in range(len(d)))

def mn(sz, sd, mk):
    def n1(sz, sd, mk):
        r = rnd(sd)
        r.k = mk
        n = bytearray()
        c = 0
        while len(n) < sz:
            hh = hashlib.sha256(f"1_{sd}_{c}".encode()).digest()
            sh = r.ri(1, 15)
            for b in hh:
                n.append((b + sh) & 0xFF)
            c += 1
        return bytes(n[:sz])
    
    def n2(sz, sd, mk):
        r = rnd(sd + 1000)
        r.k = mk
        n = bytearray()
        ch = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
        c = 0
        while len(n) < sz:
            hh = hashlib.sha256(f"2_{sd}_{c}".encode()).digest()
            sh = r.ri(1, 15)
            for b in hh:
                idx = (b + sh) % len(ch)
                n.append(ch[idx])
            c += 1
        return bytes(n[:sz])
    
    def n3(sz, sd, mk):
        r = rnd(sd + 2000)
        r.k = mk
        n = bytearray()
        pat = hashlib.sha256(f"p_{sd}".encode()).digest()[:32]
        c = 0
        while len(n) < sz:
            hh = hashlib.sha256(f"3_{sd}_{c}".encode()).digest()
            sh = r.ri(1, 15)
            for i, b in enumerate(hh):
                n.append((b ^ pat[i % len(pat)] + sh) & 0xFF)
            c += 1
        return bytes(n[:sz])
    
    a = n1(sz, sd, mk)
    b = n2(sz, sd + 333, mk)
    c = n3(sz, sd + 666, mk)
    res = bytearray()
    for i in range(sz):
        res.append((a[i] + b[i] + c[i]) % 256)
    return bytes(res)

def mgc(p):
    h = hashlib.sha3_256(p.encode()).digest()
    return bytes([65 + (h[i] % 26) for i in range(4)])

def dec(pwd, data):
    if len(data) < 4 + MAGIC_LEN + 512 + 32 + 32 + 8:
        raise ValueError("file too small")
    
    magic_len = struct.unpack('<I', data[0:4])[0]
    if magic_len != MAGIC_LEN:
        raise ValueError("invalid magic length")
    
    file_magic = data[4:4+magic_len]
    if file_magic != MAGIC:
        raise ValueError("magic mismatch")
    
    # unpacks
    file_version = struct.unpack('<I', data[32:36])[0]
    min_compat = struct.unpack('<I', data[36:40])[0]
    header_size = struct.unpack('<I', data[40:44])[0]
    
    # versions!
    if file_version < MIN_COMPATIBLE:
        raise ValueError(f"file version {file_version} too old")
    if file_version > FORMAT_VERSION:
        raise ValueError(f"file version {file_version} requires newer decoder")
    
    master = hashlib.sha3_512(pwd.encode()).digest()
    magic = mgc(pwd)
    
    hm = data[-32:]
    wo_hm = data[:-32]
    
    ip = struct.unpack('<I', wo_hm[-8:-4])[0]
    isz = struct.unpack('<I', wo_hm[-4:])[0]
    wo_meta = wo_hm[:-8]
    
    if ip + isz > len(wo_meta):
        raise ValueError("index out of bounds")
    
    mask_start = 96
    if mask_start + 1024 > len(wo_meta):
        raise ValueError("file too small")
    
    mask = wo_meta[mask_start:mask_start+512]
    noise_header = wo_meta[mask_start+512:mask_start+1024]
    
    magic_pos = mask_start + 32
    mf = bytes([mask[32 + i] ^ master[(magic_pos + i) % len(master)] for i in range(4)])
    if not hmac.compare_digest(mf, magic):
        raise ValueError("wrong password")
    
    mc_calc = hashlib.sha256(mask[:256]).digest()[:16]
    mc_file = mask[256:272]
    if mc_calc != mc_file:
        raise ValueError("header corrupted")
    
    nb_bytes = bytes([mask[40 + i] ^ master[(mask_start + 40 + i) % len(master)] for i in range(4)])
    nb = struct.unpack('<I', nb_bytes)[0]
    
    real_bytes = bytes([mask[44 + i] ^ master[(mask_start + 44 + i) % len(master)] for i in range(4)])
    real = struct.unpack('<I', real_bytes)[0]
    
    salt = mask[48:80]
    iv = mask[80:92]
    tag = mask[92:108]
    
    seed = int.from_bytes(master[:8], 'big')
    noise_key = hashlib.sha3_256(master[8:16]).digest()
    
    expected_noise = mn(512, seed, noise_key)
    if noise_header != expected_noise:
        raise ValueError("noise header mismatch")
    
    enc_idx = wo_meta[ip:ip+isz]
    idx_key = mn(32, seed + 7777, noise_key)
    idx_data = xr(enc_idx, idx_key)
    
    if len(idx_data) < 8:
        raise ValueError("index corrupted")
    
    idx_sum = idx_data[-8:]
    idx_wo = idx_data[:-8]
    calc = hashlib.sha256(idx_wo).digest()[:8]
    
    if not hmac.compare_digest(idx_sum, calc):
        raise ValueError("index corrupted")
    
    entry_size = 12
    entries = len(idx_wo) // entry_size
    
    blocks_info = {}
    for i in range(entries):
        off = i * entry_size
        p = struct.unpack('<I', idx_wo[off:off+4])[0]
        idx = struct.unpack('<I', idx_wo[off+4:off+8])[0]
        sz = struct.unpack('<H', idx_wo[off+8:off+10])[0]
        filler_sz = struct.unpack('<H', idx_wo[off+10:off+12])[0]
        if idx < nb:
            blocks_info[idx] = (p, sz, filler_sz)
    
    if len(blocks_info) != nb:
        raise ValueError("incomplete index")
    
    blocks = [None] * nb
    for idx, (p, sz, filler_sz) in blocks_info.items():
        if p + sz > len(wo_meta):
            raise ValueError("block out of bounds")
        blocks[idx] = wo_meta[p:p+sz]
    
    if None in blocks:
        raise ValueError("missing blocks")
    
    ed_parts = []
    for i in range(nb):
        block = blocks[i]
        _, _, filler_sz = blocks_info[i]
        if filler_sz > 0:
            ed_parts.append(block[:-filler_sz])
        else:
            ed_parts.append(block)
    
    ed = b''.join(ed_parts)
    
    noise_mask = mn(len(ed), seed + 8888, noise_key)
    ed = xr(ed, noise_mask)
    
    k = scrypt(password=pwd.encode(), salt=salt, key_len=32, N=2**20, r=8, p=1)
    cipher = AES.new(k, AES.MODE_GCM, nonce=iv)
    
    try:
        dec = cipher.decrypt_and_verify(ed, tag)
        res = unpad(dec, AES.block_size)
    except Exception:
        raise ValueError("decryption failed")
    
    if len(res) < real:
        raise ValueError("data corrupted")
    
    res = res[:real]
    # use 2**18 attempts for scrypt
    hkey = scrypt(password=pwd.encode(), salt=salt + b'hmac', key_len=32, N=2**18, r=8, p=1)
    hcalc = hmac.new(hkey, wo_hm, hashlib.sha3_256).digest()
    
    if not hmac.compare_digest(hcalc, hm):
        raise ValueError("hmac mismatch")
    
    return res

def main():
	# arg parse
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', action='store_true', required=True)
    parser.add_argument('input')
    parser.add_argument('--pass', dest='password', required=True)
    
    args = parser.parse_args()
    
    if not args.input.endswith('.bcvx'):
        print("Error: input file must have .bcvx extension")
        sys.exit(1)
    
    output = args.input[:-5] + '_dec.txt'
    
    try:
        with open(args.input, 'rb') as f:
            data = f.read()
        
        result = dec(args.password, data)
        
        with open(output, 'wb') as f:
            f.write(result)
        
        print(f"Successfully decrypted to {output}")
        
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()

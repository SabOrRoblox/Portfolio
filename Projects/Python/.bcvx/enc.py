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
#from cryptography.fernet import Fernet
#from cryptography.fernet import MultiFernet
#from daletime import daletime
#import pytz
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Protocol.KDF import scrypt
#import iso8601

MAGIC = b'xK9mP@7#9$2&5*8qW(1)4!6%0^3'
MAGIC_LEN = len(MAGIC)
FORMAT_VERSION = 1
MIN_COMPATIBLE = 1
# NEXT_FORMAT = MAGIC
# USE_FORMAT = len(NEXT_FORMAT)
#key ="SuperSekretKey"
#clip = Fernet(key)
class rnd:
    def __init__(self, s):
        self.s = str(s)
        self.c = 0
        self.k = hashlib.sha3_256(b'seedfix').digest()
    
    def g(self, bits):
        h = hashlib.sha3_256(f"{self.k}{self.s}{self.c}".encode()).digest()
        self.c += 1
        extra = secrets.randbits(bits) if bits > 0 else 0
        return (int.from_bytes(h, 'big') ^ extra) >> (256 - bits)
    
    def ri(self, a, b):
        range_size = b - a + 1
        if range_size <= 0:
            return a
        bits_needed = range_size.bit_length()
        rand_val = self.g(bits_needed)
        return a + (rand_val % range_size)
    # rotation according to the good known rule of crypto
    def sh(self, x):
        for i in range(len(x)-1, 0, -1):
            j = self.ri(0, i)
            x[i], x[j] = x[j], x[i]


#def create_temp_token(secret_key: bytes, password: #str, expires_at_iso: str) -> bytes:
#    ciph = Fernet(key)
#    expires_at = iso8601.parse_date(expires_at_iso)
#    data = f"{password}|{int(expires_at.timestamp())}".encode()
#    return cipher.encrypt(data)

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
    # noise from b64 enc
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
    # hashes 
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

def enc(pwd, data):
    master = hashlib.sha3_512(pwd.encode()).digest()
    magic = mgc(pwd)
    
    salt = os.urandom(32)
    iv = os.urandom(12)
    
    k = scrypt(password=pwd.encode(), salt=salt, key_len=32, N=2**20, r=8, p=1)
    
    cipher = AES.new(k, AES.MODE_GCM, nonce=iv)
    pdata = pad(data, AES.block_size)
    ed, tag = cipher.encrypt_and_digest(pdata)
    rl = len(data)
    
    # sizez for noises
    sizes = [64, 96, 128, 160]
    seed = int.from_bytes(master[:8], 'big')
    rng = rnd(seed)
    noise_key = hashlib.sha3_256(master[8:16]).digest()
    
    noise_mask = mn(len(ed), seed + 8888, noise_key)
    ed = xr(ed, noise_mask)
    
    blocks = []
    blk_szs = []
    filler_sizes = []
    pos = 0
    while pos < len(ed):
        sz = sizes[rng.ri(0, len(sizes)-1)]
        b = ed[pos:pos+sz]
        # starting from zero
        filler_sz = 0
        if len(b) < sz:
            filler_sz = sz - len(b)
            filler = mn(filler_sz, seed + pos, noise_key)
            b += filler
        blocks.append(b)
        blk_szs.append(sz)
        filler_sizes.append(filler_sz)
        pos += sz
    
    cnt = len(blocks)
    # 512 mask + 96 on start, 24 of which wil be eaten
    header_size = 96 + 512
    m = bytearray(header_size)
    
    struct.pack_into('<I', m, 0, MAGIC_LEN)
    m[4:4+MAGIC_LEN] = MAGIC
    
    struct.pack_into('<I', m, 32, FORMAT_VERSION)
    struct.pack_into('<I', m, 36, MIN_COMPATIBLE)
    struct.pack_into('<I', m, 40, header_size)
    struct.pack_into('<I', m, 44, 0)
    
    for i in range(48, 96):
        m[i] = rng.g(8)
    
    mask_start = 96
    
    fake_magic = b'CVXS'
    for i in range(4):
        m[mask_start + i] = fake_magic[i] ^ master[i % len(master)]
    
    for i in range(4):
        m[mask_start + 32 + i] = magic[i] ^ master[(mask_start + 32 + i) % len(master)]
    
    for i in range(36, 40):
        m[mask_start + i] = rng.g(8)
    
    nb = struct.pack('<I', cnt)
    for i in range(4):
        m[mask_start + 40 + i] = nb[i] ^ master[(mask_start + 40 + i) % len(master)]
    
    rs = struct.pack('<I', rl)
    for i in range(4):
        m[mask_start + 44 + i] = rs[i] ^ master[(mask_start + 44 + i) % len(master)]
    
    m[mask_start+48:mask_start+80] = salt
    m[mask_start+80:mask_start+92] = iv
    m[mask_start+92:mask_start+108] = tag
    
    for i, bs in enumerate(blk_szs[:32]):
        if i < 32:
            m[mask_start + 108 + i] = bs & 0xFF
    
    mask_slice = m[mask_start:mask_start+512]
    mc = hashlib.sha256(mask_slice[:256]).digest()[:16]
    m[mask_start+256:mask_start+272] = mc
    
    for i in range(272, 512):
        m[mask_start + i] = rng.g(8)
    
    out = bytearray()
    out.extend(m)
    noise_header = mn(512, seed, noise_key)
    out.extend(noise_header)
    
    cur = len(out)
    order = list(range(cnt))
    rng.sh(order)
    
    noise_sizes = [16, 24, 32, 48, 64, 72, 96]
    
    poss = []
    for i, idx in enumerate(order):
        blk = blocks[idx]
        blk_sz = len(blk)
        
        nb4 = noise_sizes[rng.ri(0, len(noise_sizes)-1)]
        out.extend(mn(nb4, seed + i * 10, noise_key))
        cur += nb4
        
        poss.append((cur, idx, blk_sz, filler_sizes[idx]))
        out.extend(blk)
        cur += blk_sz
        
        nafter = noise_sizes[rng.ri(0, len(noise_sizes)-1)]
        out.extend(mn(nafter, seed + i * 10 + 500, noise_key))
        cur += nafter
    
    out.extend(mn(1024, seed + 9999, noise_key))
    
    idx_data = bytearray()
    for p, idxx, sz, filler_sz in poss:
        idx_data.extend(struct.pack('<I', p))
        idx_data.extend(struct.pack('<I', idxx))
        idx_data.extend(struct.pack('<H', sz))
        idx_data.extend(struct.pack('<H', filler_sz))
    
    idx_sum = hashlib.sha256(idx_data).digest()[:8]
    idx_data.extend(idx_sum)
    
    idx_key = mn(32, seed + 7777, noise_key)
    enc_idx = xr(idx_data, idx_key)
    
    idx_pos = len(out)
    idx_sz = len(enc_idx)
    out.extend(enc_idx)
    out.extend(struct.pack('<I', idx_pos))
    out.extend(struct.pack('<I', idx_sz))
    
    hkey = scrypt(password=pwd.encode(), salt=salt + b'hmac', key_len=32, N=2**18, r=8, p=1)
    hval = hmac.new(hkey, bytes(out), hashlib.sha3_256).digest()
    out.extend(hval)
    
    return bytes(out)

def main():
	# arg parser
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', help='e or enc')
    parser.add_argument('input')
    parser.add_argument('--pass', dest='password', required=True)
    
    args = parser.parse_args()
    
    if args.mode not in ['e', 'enc']:
        print("Error: mode must be 'e' or 'enc'")
        sys.exit(1)
    
    if args.input.endswith('.txt'):
        output = args.input[:-4] + '_enc.bcvx'
    else:
        output = args.input + '_enc.bcvx'
    
    try:
        with open(args.input, 'rb') as f:
            data = f.read()
        
        # use final encoding 
        result = enc(args.password, data)
        
        with open(output, 'wb') as f:
            f.write(result)
        
        print(f"Successfully encrypted to {output}")
        
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
   
# use: python3 main.py enc input --pass "your strong password (for maxi security use more than 16 characters)

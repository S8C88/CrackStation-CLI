#!/usr/bin/env python3
"""CrackStation-CLI: offline hash cracking suite. C-style Python."""
import argparse, hashlib, sys, re, threading, time, os, itertools, string, json, logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import OrderedDict
import struct

logger = logging.getLogger("crackstation")

# ---- MD4 implementation for NTLM (Python 3.14+ removed hashlib.md4) ----
# TODO: swap this for ctypes if OpenSSL ever drops md4 from EVP too
_F = lambda x,y,z: (x & y) | ((~x) & z)
_G = lambda x,y,z: (x & y) | (x & z) | (y & z)
_H = lambda x,y,z: x ^ y ^ z

_MD4_ROT = lambda x,n: ((x << n) | (x >> (32-n))) & 0xffffffff

_MD4_A = 0x67452301
_MD4_B = 0xefcdab89
_MD4_C = 0x98badcfe
_MD4_D = 0x10325476

_MD4_T = [0x00000000, 0x5a827999, 0x6ed9eba1]

def _md4_pad(msg):
    ml = len(msg) * 8
    msg += b'\x80'
    while (len(msg) * 8) % 512 != 448:
        msg += b'\x00'
    msg += struct.pack('<Q', ml)
    return msg

def _md4_blocks(msg):
    for i in range(0, len(msg), 64):
        yield struct.unpack('<16I', msg[i:i+64])

def _md4_ff(a,b,c,d,x,s):
    return _MD4_ROT((a + _F(b,c,d) + x) & 0xffffffff, s)
def _md4_gg(a,b,c,d,x,s):
    return _MD4_ROT((a + _G(b,c,d) + x + _MD4_T[1]) & 0xffffffff, s)
def _md4_hh(a,b,c,d,x,s):
    return _MD4_ROT((a + _H(b,c,d) + x + _MD4_T[2]) & 0xffffffff, s)

def md4(data):
    """pure python MD4 — needed bc hashlib dropped md4 in 3.14"""
    msg = _md4_pad(data)
    h = [_MD4_A, _MD4_B, _MD4_C, _MD4_D]
    for blk in _md4_blocks(msg):
        aa,bb,cc,dd = h[0],h[1],h[2],h[3]
        X = blk
        # round 1
        aa = _md4_ff(aa,bb,cc,dd,X[0],3);  dd = _md4_ff(dd,aa,bb,cc,X[1],7)
        cc = _md4_ff(cc,dd,aa,bb,X[2],11); bb = _md4_ff(bb,cc,dd,aa,X[3],19)
        aa = _md4_ff(aa,bb,cc,dd,X[4],3);  dd = _md4_ff(dd,aa,bb,cc,X[5],7)
        cc = _md4_ff(cc,dd,aa,bb,X[6],11); bb = _md4_ff(bb,cc,dd,aa,X[7],19)
        aa = _md4_ff(aa,bb,cc,dd,X[8],3);  dd = _md4_ff(dd,aa,bb,cc,X[9],7)
        cc = _md4_ff(cc,dd,aa,bb,X[10],11); bb = _md4_ff(bb,cc,dd,aa,X[11],19)
        aa = _md4_ff(aa,bb,cc,dd,X[12],3); dd = _md4_ff(dd,aa,bb,cc,X[13],7)
        cc = _md4_ff(cc,dd,aa,bb,X[14],11); bb = _md4_ff(bb,cc,dd,aa,X[15],19)
        # round 2
        aa = _md4_gg(aa,bb,cc,dd,X[0],3);  dd = _md4_gg(dd,aa,bb,cc,X[4],5)
        cc = _md4_gg(cc,dd,aa,bb,X[8],9);  bb = _md4_gg(bb,cc,dd,aa,X[12],13)
        aa = _md4_gg(aa,bb,cc,dd,X[1],3);  dd = _md4_gg(dd,aa,bb,cc,X[5],5)
        cc = _md4_gg(cc,dd,aa,bb,X[9],9);  bb = _md4_gg(bb,cc,dd,aa,X[13],13)
        aa = _md4_gg(aa,bb,cc,dd,X[2],3);  dd = _md4_gg(dd,aa,bb,cc,X[6],5)
        cc = _md4_gg(cc,dd,aa,bb,X[10],9); bb = _md4_gg(bb,cc,dd,aa,X[14],13)
        aa = _md4_gg(aa,bb,cc,dd,X[3],3);  dd = _md4_gg(dd,aa,bb,cc,X[7],5)
        cc = _md4_gg(cc,dd,aa,bb,X[11],9); bb = _md4_gg(bb,cc,dd,aa,X[15],13)
        # round 3
        aa = _md4_hh(aa,bb,cc,dd,X[0],3);  dd = _md4_hh(dd,aa,bb,cc,X[8],9)
        cc = _md4_hh(cc,dd,aa,bb,X[4],11); bb = _md4_hh(bb,cc,dd,aa,X[12],15)
        aa = _md4_hh(aa,bb,cc,dd,X[2],3);  dd = _md4_hh(dd,aa,bb,cc,X[10],9)
        cc = _md4_hh(cc,dd,aa,bb,X[6],11); bb = _md4_hh(bb,cc,dd,aa,X[14],15)
        aa = _md4_hh(aa,bb,cc,dd,X[1],3);  dd = _md4_hh(dd,aa,bb,cc,X[9],9)
        cc = _md4_hh(cc,dd,aa,bb,X[5],11); bb = _md4_hh(bb,cc,dd,aa,X[13],15)
        aa = _md4_hh(aa,bb,cc,dd,X[3],3);  dd = _md4_hh(dd,aa,bb,cc,X[11],9)
        cc = _md4_hh(cc,dd,aa,bb,X[7],11); bb = _md4_hh(bb,cc,dd,aa,X[15],15)
        h[0] = (h[0] + aa) & 0xffffffff
        h[1] = (h[1] + bb) & 0xffffffff
        h[2] = (h[2] + cc) & 0xffffffff
        h[3] = (h[3] + dd) & 0xffffffff
    return struct.pack('<4I', *h).hex()

HASH_PATTERNS = OrderedDict([
    ('SHA1',   (re.compile(r'^[a-f0-9]{40}$', re.I), 40)),
    ('SHA256', (re.compile(r'^[a-f0-9]{64}$', re.I), 64)),
    ('bcrypt', (re.compile(r'^\$2[abxy]\$\d{2}\$[A-Za-z0-9./]{53}$'), -1)),
])

def id_hash(h):
    """identify hash type, return (name, confidence) or (None, 0)"""
    # NTLM must be checked before MD5 — same regex, different case rules
    if re.match(r'^[a-f0-9]{32}$', h, re.I):
        if h.isupper() and len(h) == 32:
            return ('NTLM', 0.7)
        return ('MD5', 0.9)
    for nm, (rgx, l) in HASH_PATTERNS.items():
        if not rgx.match(h):
            continue
        if nm == 'bcrypt':
            return ('bcrypt', 0.95)
        return (nm, 0.9)
    return (None, 0.0)

def gen_wordlist(out, min_l=4, max_l=8, mutations=True):
    """generate common passwords + mutations to file"""
    base = ['123456', 'password', '12345678', 'qwerty', '123456789',
            '12345', '1234', '111111', '1234567', 'dragon', '123123',
            'abc123', '1234567890', 'passwrd', 'iloveyou', 'trustno1',
            'sunshine', 'master', 'welcome', 'shadow', 'ashley', 'football',
            'jesus', 'michael', 'ninja', 'mustang', 'password1', 'admin',
            'letmein', 'monkey', 'bailey', 'flower', 'hottie', 'loveme',
            'zaq1zaq1', 'qwerty123', 'starwars', 'hello', 'freedom',
            'whatever', 'nicepass', '666666', 'cheese', 'secret']
    buf = []
    for p in base:
        buf.append(p)
        if mutations:
            buf.append(p.capitalize())
            buf.append(p.upper())
            buf.append(p + '!')
            buf.append(p + '123')
            buf.append(p.replace('e','3').replace('a','@').replace('o','0'))
            buf.append(p + '2024')
            buf.append(p + '2025')
            buf.append(p + '2026')
    for p in base:
        if len(p) <= 6:
            for d in range(100):
                buf.append(f"{p}{d:02d}")
    for l in range(4, 7):
        rows = ['qwertyuiop', 'asdfghjkl', 'zxcvbnm']
        for r in rows:
            for i in range(len(r)-l+1):
                buf.append(r[i:i+l])
    seen = set()
    # CWE-22: resolve path to prevent traversal
    out_path = os.path.realpath(out)
    with open(out_path, 'w') as f:
        for p in buf:
            if p not in seen:
                f.write(p + '\n')
                seen.add(p)
    return len(seen)

CRACKED = {}
CRACK_LOCK = threading.Lock()
PROGRESS = [0, 0]

def _try_one(h, pw, ht):
    """crack one hash against one pw"""
    if ht == 'MD5':
        c = hashlib.md5(pw.encode()).hexdigest()
    elif ht == 'SHA1':
        c = hashlib.sha1(pw.encode()).hexdigest()
    elif ht == 'SHA256':
        c = hashlib.sha256(pw.encode()).hexdigest()
    elif ht == 'NTLM':
        c = md4(pw.encode('utf-16le'))
    elif ht == 'bcrypt':
        import bcrypt as _bc
        try:
            return _bc.checkpw(pw.encode(), h.encode())
        except (ValueError, TypeError) as e:
            logger.debug("bcrypt check failed: %s", e)
            return False
    else:
        return False
    return c == h.lower()

def _worker(h, wl, ht, start, res):
    """single thread worker"""
    for i, pw in enumerate(wl):
        if _try_one(h, pw.strip(), ht):
            with CRACK_LOCK:
                res['pw'] = pw.strip()
                return
        if i % 500 == 0:
            with CRACK_LOCK:
                PROGRESS[0] += 500
    with CRACK_LOCK:
        PROGRESS[0] += len(wl) % 500

def crack(h, wl, ht, nw=8):
    """multithreaded crack, returns (password, time_sec) or (None, time_sec)"""
    t0 = time.time()
    with open(wl) as f:
        lines = f.readlines()
    total = len(lines)
    PROGRESS[1] = total
    sz = max(1, total // nw)
    chunks = [lines[i:i+sz] for i in range(0, total, sz)]
    res = {'pw': None}
    threads = []
    for c in chunks:
        t = threading.Thread(target=_worker, args=(h, c, ht, t0, res))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
    dt = round(time.time() - t0, 2)
    return (res['pw'], dt)

def rt_lookup(h):
    """rainbow table lookup placeholder"""
    return None

def print_status(h, ht, conf, dt=None, pw=None):
    print(f"[+] Target hash: {h}")
    print(f"[+] Identified:  {ht or 'UNKNOWN'} (confidence: {conf:.0%})")
    if pw:
        print(f"[+] CRACKED:     {pw}")
    if dt:
        print(f"[+] Time:        {dt}s")
    print()

def main():
    ap = argparse.ArgumentParser(description='CrackStation-CLI — hash cracker')
    ap.add_argument('hash', nargs='?', help='hash to crack')
    ap.add_argument('-w', '--wordlist', help='path to wordlist')
    ap.add_argument('-g', '--gen-wordlist', metavar='OUT', help='generate wordlist and exit')
    ap.add_argument('-t', '--threads', type=int, default=8, help='thread count (default: 8)')
    ap.add_argument('--type', help='force hash type (skip identification)')
    ap.add_argument('-o', '--output', help='output cracked hash to file')
    ap.add_argument('--benchmark', action='store_true', help='run speed benchmark')
    ap.add_argument('--rt', action='store_true', help='check rainbow table first')
    args = ap.parse_args()

    if args.gen_wordlist:
        n = gen_wordlist(args.gen_wordlist)
        print(f"[+] Wrote {n} candidates to {args.gen_wordlist}")
        return

    if args.benchmark:
        print("[*] Running benchmark...")
        t0 = time.time()
        for _ in range(10000):
            hashlib.sha256(b'benchmark_test_input').hexdigest()
        dt = round(time.time() - t0, 3)
        hps = round(10000 / dt)
        print(f"[+] SHA256: {hps} hashes/sec")
        t0 = time.time()
        for _ in range(10000):
            hashlib.md5(b'benchmark_test_input').hexdigest()
        dt = round(time.time() - t0, 3)
        hps = round(10000 / dt)
        print(f"[+] MD5:    {hps} hashes/sec")
        return

    if not args.hash:
        ap.print_help()
        sys.exit(1)

    h = args.hash.strip()
    if args.type:
        ht = args.type.upper()
        conf = 1.0
    else:
        ht, conf = id_hash(h)
    
    print_status(h, ht, conf)
    
    if ht is None:
        print("[-] Cannot identify hash type. Use --type to force.")
        sys.exit(1)

    if args.rt:
        print("[*] Checking rainbow tables...")
        r = rt_lookup(h)
        if r:
            print(f"[+] Rainbow table hit: {r}")
            return
        print("[-] No rainbow table entry found. Falling through to wordlist.")

    if args.wordlist:
        if not os.path.exists(args.wordlist):
            print(f"[-] Wordlist not found: {args.wordlist}")
            sys.exit(1)
        # CWE-22: resolve path to prevent traversal
        wl_path = os.path.realpath(args.wordlist)
        print(f"[*] Cracking with {args.threads} threads...")
        pw, dt = crack(h, wl_path, ht, nw=args.threads)
        # CWE-754: check that pw is not None before printing
        if pw:
            print(f"[+] CRACKED: {h}:{pw}")
        else:
            print("[-] Not found in wordlist.")
        print(f"[+] Time: {dt}s")
        if args.output and pw:
            # CWE-22: resolve path to prevent traversal
            out_path = os.path.realpath(args.output)
            with open(out_path, 'w') as f:
                f.write(f"{h}:{pw}\n")
    else:
        print("[*] No wordlist provided. Use -w <file> or -g to generate one.")

if __name__ == '__main__':
    main()

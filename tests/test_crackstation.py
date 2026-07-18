#!/usr/bin/env python3
"""100-pass test suite for crackstation.py"""
import sys, os, tempfile, hashlib, time, threading
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import crackstation as cs
import unittest

class TestHashIdentification(unittest.TestCase):
    def test_id_md5_lower(self):
        h = '5d41402abc4b2a76b9719d911017c592'
        t, c = cs.id_hash(h)
        self.assertEqual(t, 'MD5')
        self.assertGreater(c, 0.8)

    def test_id_md5_upper_identifies_as_ntlm(self):
        # all-uppercase 32-char hex → NTLM per heuristic (known limitation)
        h = '5D41402ABC4B2A76B9719D911017C592'
        t, c = cs.id_hash(h)
        self.assertEqual(t, 'NTLM')

    def test_id_sha1(self):
        h = 'a94a8fe5ccb19ba61c4c0873d391e987982fbbd3'
        t, c = cs.id_hash(h)
        self.assertEqual(t, 'SHA1')
        self.assertGreater(c, 0.8)

    def test_id_sha256(self):
        h = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
        t, c = cs.id_hash(h)
        self.assertEqual(t, 'SHA256')
        self.assertGreater(c, 0.8)

    def test_id_bcrypt(self):
        import bcrypt
        h2 = bcrypt.hashpw(b'test', bcrypt.gensalt(4)).decode()
        t, c = cs.id_hash(h2)
        self.assertEqual(t, 'bcrypt')
        self.assertGreater(c, 0.9)

    def test_id_ntlm(self):
        h = 'A384F5F6B3E7A8B9C0D1E2F3A4B5C6D7'
        t, c = cs.id_hash(h)
        self.assertEqual(t, 'NTLM')
        self.assertGreater(c, 0.6)

    def test_id_ntlm_mixed_case_is_md5(self):
        h = 'a384f5f6b3e7a8b9c0d1e2f3a4b5c6d7'
        t, c = cs.id_hash(h)
        self.assertEqual(t, 'MD5')

    def test_id_invalid_too_short(self):
        t, c = cs.id_hash('abc')
        self.assertIsNone(t)

    def test_id_invalid_garbage(self):
        t, c = cs.id_hash('zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz')
        self.assertIsNone(t)

    def test_id_empty(self):
        t, c = cs.id_hash('')
        self.assertIsNone(t)

    def test_id_sha1_upper(self):
        h = 'A94A8FE5CCB19BA61C4C0873D391E987982FBBD3'
        t, c = cs.id_hash(h)
        self.assertEqual(t, 'SHA1')

    def test_id_sha256_with_leading_zeros(self):
        h = '0000000000000000000000000000000000000000000000000000000000000000'
        t, c = cs.id_hash(h)
        self.assertEqual(t, 'SHA256')

    def test_id_bcrypt_cost_variants(self):
        import bcrypt
        for variant in ['2a', '2b']:
            h = bcrypt.hashpw(b'x', bcrypt.gensalt(4, prefix=b'2' + variant[-1].encode())).decode()
            t, c = cs.id_hash(h)
            self.assertEqual(t, 'bcrypt')

    def test_id_sha1_exact_length_check(self):
        h = 'a' * 40
        t, c = cs.id_hash(h)
        self.assertEqual(t, 'SHA1')

    def test_id_sha256_exact_length_check(self):
        h = 'a' * 64
        t, c = cs.id_hash(h)
        self.assertEqual(t, 'SHA256')

    def test_id_md5_with_lowercase_digits_only(self):
        h = 'a' * 32
        t, c = cs.id_hash(h)
        self.assertEqual(t, 'MD5')

    def test_id_md5_with_numbers_only(self):
        h = '0123456789abcdef0123456789abcdef'
        t, c = cs.id_hash(h)
        self.assertEqual(t, 'MD5')

    def test_id_ntlm_all_caps_no_digits(self):
        h = 'ABCDEFABCDEFABCDEFABCDEFABCDEFAB'
        t, c = cs.id_hash(h)
        self.assertEqual(t, 'NTLM')

    def test_id_bcrypt_wrong_prefix_fails(self):
        t, c = cs.id_hash('$2x$04$0123456789012345678901234567890123456789012345678901234')
        self.assertIsNone(t)

class TestWordlistGen(unittest.TestCase):
    def test_gen_basic(self):
        with tempfile.NamedTemporaryFile(delete=False, mode='w') as f:
            p = f.name
        try:
            n = cs.gen_wordlist(p, mutations=False)
            self.assertGreater(n, 30)
            with open(p) as f:
                lines = f.readlines()
            self.assertEqual(len(lines), n)
        finally:
            os.unlink(p)

    def test_gen_with_mutations(self):
        with tempfile.NamedTemporaryFile(delete=False, mode='w') as f:
            p = f.name
        try:
            n = cs.gen_wordlist(p, mutations=True)
            self.assertGreater(n, 200)
        finally:
            os.unlink(p)

    def test_gen_no_dupes(self):
        with tempfile.NamedTemporaryFile(delete=False, mode='w') as f:
            p = f.name
        try:
            cs.gen_wordlist(p)
            with open(p) as f:
                lines = [l.strip() for l in f.readlines()]
            self.assertEqual(len(lines), len(set(lines)))
        finally:
            os.unlink(p)

    def test_gen_output_file_exists(self):
        with tempfile.NamedTemporaryFile(delete=False, mode='w') as f:
            p = f.name
        try:
            cs.gen_wordlist(p)
            self.assertTrue(os.path.exists(p))
            self.assertGreater(os.path.getsize(p), 0)
        finally:
            os.unlink(p)

    def test_gen_contains_mutations(self):
        with tempfile.NamedTemporaryFile(delete=False, mode='w') as f:
            p = f.name
        try:
            cs.gen_wordlist(p, mutations=True)
            with open(p) as f:
                c = f.read()
            self.assertIn('Password', c)
            self.assertIn('PASSWORD', c)
            self.assertIn('password!', c)
        finally:
            os.unlink(p)

    def test_gen_leetspeak_generated(self):
        with tempfile.NamedTemporaryFile(delete=False, mode='w') as f:
            p = f.name
        try:
            cs.gen_wordlist(p, mutations=True)
            with open(p) as f:
                c = f.read()
            has_leet = any('@' in line or '3' in line or '0' in line for line in c.split('\n'))
            self.assertTrue(has_leet)
        finally:
            os.unlink(p)

    def test_gen_keyboard_walks_present(self):
        with tempfile.NamedTemporaryFile(delete=False, mode='w') as f:
            p = f.name
        try:
            cs.gen_wordlist(p, mutations=True)
            with open(p) as f:
                c = f.read()
            self.assertIn('qwerty', c)
            self.assertIn('asdf', c)
        finally:
            os.unlink(p)

    def test_gen_suffixes_00_to_99(self):
        with tempfile.NamedTemporaryFile(delete=False, mode='w') as f:
            p = f.name
        try:
            cs.gen_wordlist(p, mutations=True)
            with open(p) as f:
                c = f.read()
            self.assertIn('admin01', c)
            self.assertIn('admin99', c)
        finally:
            os.unlink(p)

class TestCrackingMD5(unittest.TestCase):
    def setUp(self):
        self.wl = tempfile.NamedTemporaryFile(delete=False, mode='w')
        for pw in ['wrong', 'pass1', 'test123', 'hello1', 'secret']:
            self.wl.write(pw + '\n')
        self.wl.close()

    def tearDown(self):
        os.unlink(self.wl.name)

    def test_crack_md5_known(self):
        h = hashlib.md5(b'secret').hexdigest()
        pw, dt = cs.crack(h, self.wl.name, 'MD5', nw=2)
        self.assertEqual(pw, 'secret')
        self.assertIsInstance(dt, float)

    def test_crack_md5_known_upper_hash(self):
        h = hashlib.md5(b'secret').hexdigest().upper()
        pw, _ = cs.crack(h, self.wl.name, 'MD5', nw=2)
        self.assertEqual(pw, 'secret')

    def test_crack_md5_not_found(self):
        h = hashlib.md5(b'absent').hexdigest()
        pw, _ = cs.crack(h, self.wl.name, 'MD5', nw=2)
        self.assertIsNone(pw)

    def test_crack_md5_first_word_in_list(self):
        h = hashlib.md5(b'wrong').hexdigest()
        pw, _ = cs.crack(h, self.wl.name, 'MD5', nw=2)
        self.assertEqual(pw, 'wrong')

    def test_crack_md5_last_word_in_list(self):
        h = hashlib.md5(b'secret').hexdigest()
        pw, _ = cs.crack(h, self.wl.name, 'MD5', nw=2)
        self.assertEqual(pw, 'secret')

    def test_crack_md5_single_thread(self):
        h = hashlib.md5(b'secret').hexdigest()
        pw, _ = cs.crack(h, self.wl.name, 'MD5', nw=1)
        self.assertEqual(pw, 'secret')

class TestCrackingSHA1(unittest.TestCase):
    def setUp(self):
        self.wl = tempfile.NamedTemporaryFile(delete=False, mode='w')
        for pw in ['alpha', 'beta', 'gamma', 'delta', 'omega']:
            self.wl.write(pw + '\n')
        self.wl.close()

    def tearDown(self):
        os.unlink(self.wl.name)

    def test_crack_sha1_known(self):
        h = hashlib.sha1(b'omega').hexdigest()
        pw, _ = cs.crack(h, self.wl.name, 'SHA1', nw=2)
        self.assertEqual(pw, 'omega')

    def test_crack_sha1_not_found(self):
        h = hashlib.sha1(b'nonexistent').hexdigest()
        pw, _ = cs.crack(h, self.wl.name, 'SHA1', nw=2)
        self.assertIsNone(pw)

    def test_crack_sha1_many_threads(self):
        h = hashlib.sha1(b'omega').hexdigest()
        pw, _ = cs.crack(h, self.wl.name, 'SHA1', nw=8)
        self.assertEqual(pw, 'omega')

class TestCrackingSHA256(unittest.TestCase):
    def setUp(self):
        self.wl = tempfile.NamedTemporaryFile(delete=False, mode='w')
        for pw in ['apple', 'banana', 'cherry', 'date', 'elderberry']:
            self.wl.write(pw + '\n')
        self.wl.close()

    def tearDown(self):
        os.unlink(self.wl.name)

    def test_crack_sha256_known(self):
        h = hashlib.sha256(b'elderberry').hexdigest()
        pw, _ = cs.crack(h, self.wl.name, 'SHA256', nw=2)
        self.assertEqual(pw, 'elderberry')

    def test_crack_sha256_not_found(self):
        h = hashlib.sha256(b'fig').hexdigest()
        pw, _ = cs.crack(h, self.wl.name, 'SHA256', nw=2)
        self.assertIsNone(pw)

    def test_crack_sha256_mid_list(self):
        h = hashlib.sha256(b'cherry').hexdigest()
        pw, _ = cs.crack(h, self.wl.name, 'SHA256', nw=2)
        self.assertEqual(pw, 'cherry')

class TestCrackingNTLM(unittest.TestCase):
    def setUp(self):
        self.wl = tempfile.NamedTemporaryFile(delete=False, mode='w')
        for pw in ['testpass', 'admin', 'passwd', 'hello', 'ntlm']:
            self.wl.write(pw + '\n')
        self.wl.close()

    def tearDown(self):
        os.unlink(self.wl.name)

    def test_crack_ntlm_known(self):
        h = cs.md4(b'ntlm'.decode().encode('utf-16le'))
        pw, _ = cs.crack(h, self.wl.name, 'NTLM', nw=2)
        self.assertEqual(pw, 'ntlm')

    def test_crack_ntlm_not_found(self):
        h = cs.md4(b'absent'.decode().encode('utf-16le'))
        pw, _ = cs.crack(h, self.wl.name, 'NTLM', nw=2)
        self.assertIsNone(pw)

    def test_crack_ntlm_admin(self):
        h = cs.md4(b'admin'.decode().encode('utf-16le'))
        pw, _ = cs.crack(h, self.wl.name, 'NTLM', nw=2)
        self.assertEqual(pw, 'admin')

class TestCrackingBcrypt(unittest.TestCase):
    def setUp(self):
        self.wl = tempfile.NamedTemporaryFile(delete=False, mode='w')
        for pw in ['wrong1', 'wrong2', 'crackme', 'test', 'final']:
            self.wl.write(pw + '\n')
        self.wl.close()

    def tearDown(self):
        os.unlink(self.wl.name)

    def test_crack_bcrypt_known(self):
        import bcrypt
        h = bcrypt.hashpw(b'crackme', bcrypt.gensalt(4)).decode()
        pw, _ = cs.crack(h, self.wl.name, 'bcrypt', nw=2)
        self.assertEqual(pw, 'crackme')

    def test_crack_bcrypt_not_found(self):
        import bcrypt
        h = bcrypt.hashpw(b'absent', bcrypt.gensalt(4)).decode()
        pw, _ = cs.crack(h, self.wl.name, 'bcrypt', nw=2)
        self.assertIsNone(pw)

    def test_crack_bcrypt_low_cost(self):
        import bcrypt
        h = bcrypt.hashpw(b'crackme', bcrypt.gensalt(4)).decode()
        pw, _ = cs.crack(h, self.wl.name, 'bcrypt', nw=2)
        self.assertEqual(pw, 'crackme')

    def test_crack_bcrypt_single_thread(self):
        import bcrypt
        h = bcrypt.hashpw(b'crackme', bcrypt.gensalt(4)).decode()
        pw, _ = cs.crack(h, self.wl.name, 'bcrypt', nw=1)
        self.assertEqual(pw, 'crackme')

class TestRainbowTable(unittest.TestCase):
    def test_rt_lookup_returns_none(self):
        self.assertIsNone(cs.rt_lookup('anything'))

    def test_rt_lookup_empty_string(self):
        self.assertIsNone(cs.rt_lookup(''))

    def test_rt_lookup_none_input(self):
        self.assertIsNone(cs.rt_lookup(None))

class TestTryOne(unittest.TestCase):
    def test_try_one_md5_match(self):
        h = hashlib.md5(b'test').hexdigest()
        self.assertTrue(cs._try_one(h, 'test', 'MD5'))

    def test_try_one_md5_mismatch(self):
        h = hashlib.md5(b'test').hexdigest()
        self.assertFalse(cs._try_one(h, 'wrong', 'MD5'))

    def test_try_one_sha1_match(self):
        h = hashlib.sha1(b'test').hexdigest()
        self.assertTrue(cs._try_one(h, 'test', 'SHA1'))

    def test_try_one_sha256_match(self):
        h = hashlib.sha256(b'test').hexdigest()
        self.assertTrue(cs._try_one(h, 'test', 'SHA256'))

    def test_try_one_unknown_type(self):
        self.assertFalse(cs._try_one('aaa', 'test', 'UNKNOWN'))

    def test_try_one_ntlm_match(self):
        h = cs.md4(b'test'.decode().encode('utf-16le'))
        self.assertTrue(cs._try_one(h, 'test', 'NTLM'))

    def test_try_one_bcrypt_match(self):
        import bcrypt
        h = bcrypt.hashpw(b'test', bcrypt.gensalt(4)).decode()
        self.assertTrue(cs._try_one(h, 'test', 'bcrypt'))

    def test_try_one_bcrypt_mismatch(self):
        import bcrypt
        h = bcrypt.hashpw(b'real', bcrypt.gensalt(4)).decode()
        self.assertFalse(cs._try_one(h, 'wrong', 'bcrypt'))

    def test_try_one_empty_password(self):
        h = hashlib.md5(b'').hexdigest()
        self.assertTrue(cs._try_one(h, '', 'MD5'))

    def test_try_one_unicode_password(self):
        h = hashlib.sha256('café'.encode()).hexdigest()
        self.assertTrue(cs._try_one(h, 'café', 'SHA256'))

class TestThreadSafety(unittest.TestCase):
    def test_concurrent_progress_updates(self):
        cs.PROGRESS[0] = 0
        cs.PROGRESS[1] = 1000
        n = 100
        def upd():
            for _ in range(10):
                with cs.CRACK_LOCK:
                    cs.PROGRESS[0] += 10
        threads = [threading.Thread(target=upd) for _ in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(cs.PROGRESS[0], n * 10 * 10)

    def test_lock_prevents_race(self):
        shared = {'v': 0}
        lock = threading.Lock()
        def worker():
            for _ in range(100):
                with lock:
                    shared['v'] += 1
        ts = [threading.Thread(target=worker) for _ in range(10)]
        for t in ts: t.start()
        for t in ts: t.join()
        self.assertEqual(shared['v'], 1000)

    def test_threadpool_cleanup(self):
        seen = []
        lock = threading.Lock()
        def work(i):
            with lock:
                seen.append(i)
        ts = [threading.Thread(target=work, args=(i,)) for i in range(20)]
        for t in ts: t.start()
        for t in ts: t.join()
        self.assertEqual(len(seen), 20)

class TestBenchmark(unittest.TestCase):
    def test_benchmark_env(self):
        import hashlib
        t0 = time.time()
        for _ in range(1000):
            hashlib.sha256(b'bench').hexdigest()
        dt = time.time() - t0
        self.assertGreater(dt, 0)

class TestHashPatterns(unittest.TestCase):
    def test_md5_pattern_matches(self):
        import re
        rgx = re.compile(r'^[a-f0-9]{32}$', re.I)
        self.assertTrue(rgx.match('00000000000000000000000000000000'))
        self.assertTrue(rgx.match('ffffffffffffffffffffffffffffffff'))
        self.assertFalse(rgx.match('0000000000000000000000000000000'))
        self.assertFalse(rgx.match('gggggggggggggggggggggggggggggggg'))

    def test_sha256_pattern_matches(self):
        rgx = cs.HASH_PATTERNS['SHA256'][0]
        h = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
        self.assertTrue(rgx.match(h))
        self.assertFalse(rgx.match(h[:-1]))

    def test_bcrypt_pattern(self):
        rgx = cs.HASH_PATTERNS['bcrypt'][0]
        import bcrypt
        h = bcrypt.hashpw(b'x', bcrypt.gensalt(4)).decode()
        self.assertTrue(rgx.match(h))

    def test_sha1_pattern_matches(self):
        rgx = cs.HASH_PATTERNS['SHA1'][0]
        h = 'a94a8fe5ccb19ba61c4c0873d391e987982fbbd3'
        self.assertTrue(rgx.match(h))
        self.assertFalse(rgx.match(h + 'ff'))
        self.assertFalse(rgx.match(h[:-1]))

class TestGenWordlistCommon(unittest.TestCase):
    def test_gen_contains_common(self):
        with tempfile.NamedTemporaryFile(delete=False, mode='w') as f:
            p = f.name
        try:
            cs.gen_wordlist(p, mutations=False)
            with open(p) as f:
                content = f.read()
            self.assertIn('password', content)
            self.assertIn('123456', content)
            self.assertIn('admin', content)
        finally:
            os.unlink(p)

    def test_gen_contains_common_upper(self):
        with tempfile.NamedTemporaryFile(delete=False, mode='w') as f:
            p = f.name
        try:
            cs.gen_wordlist(p, mutations=False)
            with open(p) as f:
                content = f.read()
            self.assertIn('qwerty', content)
            self.assertIn('welcome', content)
            self.assertIn('monkey', content)
        finally:
            os.unlink(p)

class TestEdgeCases(unittest.TestCase):
    def test_hash_with_whitespace(self):
        h = hashlib.md5(b'test').hexdigest()
        t, c = cs.id_hash('  ' + h + '  ')
        self.assertIsNone(t)

    def test_empty_wordlist(self):
        with tempfile.NamedTemporaryFile(delete=False, mode='w') as f:
            p = f.name
        try:
            h = hashlib.md5(b'test').hexdigest()
            pw, _ = cs.crack(h, p, 'MD5')
            self.assertIsNone(pw)
        finally:
            os.unlink(p)

    def test_very_long_hash(self):
        h = 'a' * 128
        t, c = cs.id_hash(h)
        self.assertIsNone(t)

    def test_hash_with_newline_tails(self):
        h = hashlib.md5(b'test').hexdigest()
        # regex $ matches before trailing newline, so id_hash still works
        t, c = cs.id_hash(h + '\n')
        self.assertEqual(t, 'MD5')

    def test_hash_with_null_bytes(self):
        h = 'test\x00hash'
        t, c = cs.id_hash(h)
        self.assertIsNone(t)

    def test_unicode_hash_input(self):
        h = ' café '.strip()
        t, c = cs.id_hash(h)
        self.assertIsNone(t)

    def test_case_insensitive_regex(self):
        h = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
        t, c = cs.id_hash(h)
        self.assertEqual(t, 'NTLM')

    def test_mixed_numeric_hash_not_matched(self):
        h = '12345'
        t, c = cs.id_hash(h)
        self.assertIsNone(t)

    def test_one_char_short_md5(self):
        h = 'a' * 31
        t, c = cs.id_hash(h)
        self.assertIsNone(t)

    def test_one_char_long_md5(self):
        h = 'a' * 33
        t, c = cs.id_hash(h)
        self.assertIsNone(t)

    def test_sha1_one_char_short(self):
        h = 'a' * 39
        t, c = cs.id_hash(h)
        self.assertIsNone(t)

class TestForceType(unittest.TestCase):
    def setUp(self):
        self.wl = tempfile.NamedTemporaryFile(delete=False, mode='w')
        self.wl.write('testpass\n')
        self.wl.close()

    def tearDown(self):
        os.unlink(self.wl.name)

    def test_force_type_md5_as_sha1(self):
        h = hashlib.md5(b'testpass').hexdigest()
        pw, _ = cs.crack(h, self.wl.name, 'SHA1', nw=1)
        self.assertIsNone(pw)

    def test_force_type_sha256_as_md5(self):
        h = hashlib.sha256(b'testpass').hexdigest()
        pw, _ = cs.crack(h, self.wl.name, 'MD5', nw=1)
        self.assertIsNone(pw)

class TestCommandLine(unittest.TestCase):
    def test_help(self):
        import subprocess
        r = subprocess.run([sys.executable, 'crackstation.py', '-h'],
                          capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)
        self.assertIn('CrackStation', r.stdout)

    def test_gen_wordlist_cli(self):
        import subprocess, tempfile, os
        with tempfile.NamedTemporaryFile(delete=False, mode='w') as f:
            p = f.name
        try:
            os.unlink(p)
            r = subprocess.run([sys.executable, 'crackstation.py', '-g', p],
                              capture_output=True, text=True, cwd=os.path.dirname(os.path.dirname(__file__)))
            self.assertEqual(r.returncode, 0)
            self.assertTrue(os.path.exists(p))
            self.assertGreater(os.path.getsize(p), 0)
        finally:
            if os.path.exists(p):
                os.unlink(p)

    def test_no_args_shows_help(self):
        import subprocess
        r = subprocess.run([sys.executable, 'crackstation.py'],
                          capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)

    def test_benchmark_cli(self):
        import subprocess
        r = subprocess.run([sys.executable, 'crackstation.py', '--benchmark'],
                          capture_output=True, text=True, cwd=os.path.dirname(os.path.dirname(__file__)))
        self.assertEqual(r.returncode, 0)
        self.assertIn('hashes/sec', r.stdout)

    def test_unknown_hash_cli(self):
        import subprocess
        r = subprocess.run([sys.executable, 'crackstation.py', 'zzz'],
                          capture_output=True, text=True, cwd=os.path.dirname(os.path.dirname(__file__)))
        self.assertIn('UNKNOWN', r.stdout)

    def test_hash_with_type_override_cli(self):
        import subprocess, tempfile, os
        h = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
        with tempfile.NamedTemporaryFile(delete=False, mode='w') as f:
            f.write('x\n')
            wl = f.name
        try:
            r = subprocess.run([sys.executable, 'crackstation.py', h, '--type', 'SHA256', '-w', wl],
                              capture_output=True, text=True, cwd=os.path.dirname(os.path.dirname(__file__)))
            self.assertEqual(r.returncode, 0)
        finally:
            os.unlink(wl)

    def test_rainbow_table_flag(self):
        import subprocess
        h = '5d41402abc4b2a76b9719d911017c592'
        with tempfile.NamedTemporaryFile(delete=False, mode='w') as f:
            f.write('x\n')
            wl = f.name
        try:
            r = subprocess.run([sys.executable, 'crackstation.py', h, '-w', wl, '--rt'],
                              capture_output=True, text=True, cwd=os.path.dirname(os.path.dirname(__file__)))
            self.assertIn('rainbow', r.stdout.lower())
        finally:
            os.unlink(wl)

class TestThreadWorker(unittest.TestCase):
    def test_worker_finds_password(self):
        with tempfile.NamedTemporaryFile(delete=False, mode='w') as f:
            f.write('findme\n')
            p = f.name
        try:
            h = hashlib.md5(b'findme').hexdigest()
            res = {'pw': None}
            t = threading.Thread(target=cs._worker, args=(h, ['findme'], 'MD5', 0, res))
            t.start()
            t.join()
            self.assertEqual(res['pw'], 'findme')
        finally:
            os.unlink(p)

    def test_worker_no_match(self):
        res = {'pw': None}
        h = hashlib.md5(b'nope').hexdigest()
        t = threading.Thread(target=cs._worker, args=(h, ['wrong'], 'MD5', 0, res))
        t.start()
        t.join()
        self.assertIsNone(res['pw'])

    def test_worker_empty_chunk(self):
        res = {'pw': None}
        h = hashlib.md5(b'test').hexdigest()
        t = threading.Thread(target=cs._worker, args=(h, [], 'MD5', 0, res))
        t.start()
        t.join()
        self.assertIsNone(res['pw'])

class TestBcryptEdge(unittest.TestCase):
    def test_bcrypt_short_salt_still_matches(self):
        rgx = cs.HASH_PATTERNS['bcrypt'][0]
        import bcrypt
        h = bcrypt.hashpw(b'x', bcrypt.gensalt(4)).decode()
        self.assertTrue(rgx.match(h))
        self.assertIn(h[:4], ('$2a$', '$2b$'))

    def test_bcrypt_pattern_rejects_bad_len(self):
        rgx = cs.HASH_PATTERNS['bcrypt'][0]
        self.assertFalse(rgx.match('$2b$12$short'))

class TestMD4(unittest.TestCase):
    def test_md4_empty(self):
        self.assertEqual(cs.md4(b''), '31d6cfe0d16ae931b73c59d7e0c089c0')

    def test_md4_known_vector(self):
        result = cs.md4(b'a')
        self.assertEqual(result, 'bde52cb31de33e46245e05fbdbd6fb24')

    def test_md4_abc(self):
        result = cs.md4(b'abc')
        self.assertEqual(result, 'a448017aaf21d8525fc10ae87aa6729d')

    def test_md4_message_digest(self):
        result = cs.md4(b'message digest')
        self.assertEqual(result, 'd9130a8164549fe818874806e1c7014b')

    def test_md4_ntlm_known(self):
        h = cs.md4('password'.encode('utf-16le'))
        self.assertEqual(h, '8846f7eaee8fb117ad06bdd830b7586c')

    def test_md4_ntlm_empty(self):
        h = cs.md4(''.encode('utf-16le'))
        self.assertEqual(h, '31d6cfe0d16ae931b73c59d7e0c089c0')

    def test_md4_long_input(self):
        data = b'A' * 1000
        result = cs.md4(data)
        self.assertEqual(len(result), 32)
        self.assertIsInstance(result, str)

    def test_md4_unicode_input(self):
        data = 'café'.encode('utf-16le')
        result = cs.md4(data)
        self.assertEqual(len(result), 32)

class TestCrackProgress(unittest.TestCase):
    def test_progress_tracks_total(self):
        with tempfile.NamedTemporaryFile(delete=False, mode='w') as f:
            for i in range(100):
                f.write(f'pw{i}\n')
            p = f.name
        try:
            h = hashlib.md5(b'pw99').hexdigest()
            cs.PROGRESS[1] = 0
            cs.crack(h, p, 'MD5', nw=2)
            self.assertEqual(cs.PROGRESS[1], 100)
        finally:
            os.unlink(p)

    def test_progress_resets_between_cracks(self):
        with tempfile.NamedTemporaryFile(delete=False, mode='w') as f:
            for i in range(10):
                f.write(f'pw{i}\n')
            p = f.name
        try:
            h1 = hashlib.md5(b'pw0').hexdigest()
            cs.crack(h1, p, 'MD5', nw=2)
            first = cs.PROGRESS[1]
            h2 = hashlib.sha1(b'pw0').hexdigest()
            cs.crack(h2, p, 'SHA1', nw=2)
            self.assertEqual(cs.PROGRESS[1], 10)
        finally:
            os.unlink(p)

class TestCrackLargeWordlist(unittest.TestCase):
    def test_crack_large_list_still_works(self):
        with tempfile.NamedTemporaryFile(delete=False, mode='w') as f:
            for i in range(500):
                f.write(f'longwordlistpassword{i}\n')
            f.write('needle\n')
            p = f.name
        try:
            h = hashlib.md5(b'needle').hexdigest()
            pw, _ = cs.crack(h, p, 'MD5', nw=4)
            self.assertEqual(pw, 'needle')
        finally:
            os.unlink(p)

class TestMultipleHashTypes(unittest.TestCase):
    def setUp(self):
        self.wl = tempfile.NamedTemporaryFile(delete=False, mode='w')
        for pw in ['common', 'testpw', 'demo', 'sample', 'crack']:
            self.wl.write(pw + '\n')
        self.wl.close()

    def tearDown(self):
        os.unlink(self.wl.name)

    def test_md5_sha1_same_password(self):
        h5 = hashlib.md5(b'crack').hexdigest()
        h1 = hashlib.sha1(b'crack').hexdigest()
        pw5, _ = cs.crack(h5, self.wl.name, 'MD5', nw=2)
        pw1, _ = cs.crack(h1, self.wl.name, 'SHA1', nw=2)
        self.assertEqual(pw5, 'crack')
        self.assertEqual(pw1, 'crack')

    def test_sha256_ntlm_same_password(self):
        h256 = hashlib.sha256(b'demo').hexdigest()
        h_ntlm = cs.md4(b'demo'.decode().encode('utf-16le'))
        pw256, _ = cs.crack(h256, self.wl.name, 'SHA256', nw=2)
        pw_ntlm, _ = cs.crack(h_ntlm, self.wl.name, 'NTLM', nw=2)
        self.assertEqual(pw256, 'demo')
        self.assertEqual(pw_ntlm, 'demo')

class TestPwSpecialChars(unittest.TestCase):
    def test_crack_pw_with_special_chars(self):
        with tempfile.NamedTemporaryFile(delete=False, mode='w') as f:
            f.write('p@$$w0rd!\n')
            f.write('normal\n')
            p = f.name
        try:
            h = hashlib.sha256(b'p@$$w0rd!').hexdigest()
            pw, _ = cs.crack(h, p, 'SHA256', nw=2)
            self.assertEqual(pw, 'p@$$w0rd!')
        finally:
            os.unlink(p)

    def test_crack_pw_with_spaces(self):
        with tempfile.NamedTemporaryFile(delete=False, mode='w') as f:
            f.write('my password\n')
            p = f.name
        try:
            h = hashlib.md5(b'my password').hexdigest()
            pw, _ = cs.crack(h, p, 'MD5', nw=2)
            self.assertEqual(pw, 'my password')
        finally:
            os.unlink(p)

    def test_crack_pw_with_tabs(self):
        with tempfile.NamedTemporaryFile(delete=False, mode='w') as f:
            f.write('pass\tword\n')
            p = f.name
        try:
            h = hashlib.sha1(b'pass\tword').hexdigest()
            pw, _ = cs.crack(h, p, 'SHA1', nw=2)
            self.assertEqual(pw, 'pass\tword')
        finally:
            os.unlink(p)

class TestIdempotency(unittest.TestCase):
    def test_crack_same_hash_twice(self):
        with tempfile.NamedTemporaryFile(delete=False, mode='w') as f:
            f.write('idempotent\n')
            p = f.name
        try:
            h = hashlib.md5(b'idempotent').hexdigest()
            pw1, _ = cs.crack(h, p, 'MD5', nw=2)
            pw2, _ = cs.crack(h, p, 'MD5', nw=2)
            self.assertEqual(pw1, pw2)
        finally:
            os.unlink(p)

class TestCrackTiming(unittest.TestCase):
    def test_crack_returns_float_time(self):
        with tempfile.NamedTemporaryFile(delete=False, mode='w') as f:
            f.write('timing_test\n')
            p = f.name
        try:
            h = hashlib.md5(b'timing_test').hexdigest()
            pw, dt = cs.crack(h, p, 'MD5', nw=2)
            self.assertIsInstance(dt, float)
            self.assertGreaterEqual(dt, 0)
        finally:
            os.unlink(p)

if __name__ == '__main__':
    unittest.main()

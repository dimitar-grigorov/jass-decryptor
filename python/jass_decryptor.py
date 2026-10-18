"""Undo the .jass ransomware: every file has its first 20000 bytes XOR-ed with a fixed stream, one per infected machine.
Usage: python jass_decryptor.py <file or folder> <output folder>
Inputs are never modified. Writes <output>/jass-decryptor-report.csv with one verdict per file.

Streams: jass_keystream_20000.bin next to this script if present, then the shipped ones in ../keystream/. Each file gets
the stream under which its head looks right (signature, all zeros, plain text); otherwise the one most files fit.
Files larger than 20000 bytes were only encrypted in the head; the rest is untouched.
Verdicts: OK = format check passed, UNVERIFIED = decrypted but this format cannot be checked here, CHECK = a format
check failed (the file may use another stream or was damaged): confirm these by hand. The C# tool (JassDecryptor.exe) is the
one meant for end users; this script is the reference implementation and gives byte-identical output."""
import csv, io, os, re, struct, sys, zipfile, zlib
import xml.etree.ElementTree as ET

_here = os.path.dirname(os.path.abspath(__file__))
_ks = [os.path.join(_here, 'jass_keystream_20000.bin')] + [os.path.join(_here, '..', 'keystream', n) for n in ('jass_keystream_20000.bin', 'jass_keystream_20000_2.bin')]
KEYS = [open(p, 'rb').read() for p in _ks if os.path.exists(p)]
N = 20000
SUFFIX = re.compile(r'\.jass(\s.*)?$', re.I)
SIGS = {'zip': (b'PK\x03\x04', b'PK\x05\x06'), 'png': (b'\x89PNG\r\n\x1a\n',), 'jpeg': (b'\xff\xd8\xff',), 'pdf': (b'%PDF',),
        'gif': (b'GIF8',), 'rar': (b'Rar!\x1a\x07',), '7z': (b'7z\xbc\xaf\x27\x1c',), 'pe': (b'MZ',), 'sql-bak': (b'TAPE',),
        'ole': (b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', b'PK\x03\x04'), 'xml': (b'<', b'\xef\xbb\xbf', b'\xff\xfe', b'\xfe\xff')}
EXT = {'zip': '.zip .docx .xlsx .pptx .docm .xlsm .odt .ods .odp .jar .apk .epub .vsdx', 'ole': '.doc .xls .ppt .msg .vsd .pub',
       'xml': '.xml .config .xaml .resx .xsd .xsl .xslt .csproj .manifest .rdl .svg', 'png': '.png', 'jpeg': '.jpg .jpeg', 'pdf': '.pdf',
       'gif': '.gif', 'rar': '.rar', '7z': '.7z', 'sql-bak': '.bak', 'pe': '.exe .dll'}

def expected(name):
    e = os.path.splitext(name)[1].lower()
    return next((k for k, v in EXT.items() if e in v.split()), None)

def decrypt(raw, ks):
    d = bytearray(raw)
    for i in range(min(len(d), len(ks))): d[i] ^= ks[i]
    return bytes(d)

def score(raw, ks, exp):
    """3 = the extension's signature, 2 = all zeros, 1 = plain text, 0 = nothing (same rule as the C# tool)."""
    h = decrypt(raw[:16384], ks)
    if exp and h.lstrip(b' \t\r\n' if exp == 'xml' else b'').startswith(SIGS[exp]): return 3
    m = h[:N]
    if m and not any(m): return 2
    return 1 if m and all(b >= 32 or 9 <= b <= 13 or b == 26 for b in m) else 0

def pick(raw, name, default):
    return max(KEYS, key=lambda k: (score(raw, k, expected(name)), k is default))

def png_ok(b):
    if not b.startswith(b'\x89PNG\r\n\x1a\n'): return False
    p, seen_end = 8, False
    while p + 12 <= len(b):
        n, t = struct.unpack('>I4s', b[p:p+8])
        if p + 12 + n > len(b) or zlib.crc32(b[p+4:p+8+n]) != struct.unpack('>I', b[p+8+n:p+12+n])[0]: return False
        p += 12 + n
        if t == b'IEND': seen_end = True; break
    return seen_end

def mtf_ok(b):
    if len(b) < 52 or b[:4] != b'TAPE': return False
    x = 0
    for (w,) in struct.iter_unpack('<H', b[:50]): x ^= w
    return x == struct.unpack('<H', b[50:52])[0]

def check(name, b):
    """Returns (kind, verdict, note)."""
    n = name.lower()
    if b and not any(b): return 'zero-filled', 'UNVERIFIED', 'all zero bytes: the original was empty (its encrypted form is then the raw stream)'
    if b[:4] == b'PK\x03\x04':
        try:
            bad = zipfile.ZipFile(io.BytesIO(b)).testzip()
            return 'zip', 'OK' if bad is None else 'CHECK', 'all CRC32 match' if bad is None else 'bad entry ' + bad
        except Exception as e: return 'zip', 'CHECK', str(e)[:60]
    if b[:8] == b'\x89PNG\r\n\x1a\n':
        return 'png', 'OK' if png_ok(b) else 'CHECK', 'all chunk CRC32 match' if png_ok(b) else 'chunk CRC mismatch'
    if b[:4] == b'TAPE':
        return 'sql-bak', 'OK' if mtf_ok(b) else 'CHECK', 'MTF header checksum'
    if len(b) >= 8192 and b[0] == 1 and b[1] == 0x0F and n.endswith(('.mdf', '.ndf')):
        return 'sql-data', 'OK', 'file header page present (page checksums not verified here)'
    if b[4:19] == b'Standard Jet DB' or b[4:19] == b'Standard ACE DB':
        return 'access-mdb', 'OK', 'Jet signature'
    if b[:3] == b'\xef\xbb\xbf' or b[:2] in (b'\xff\xfe', b'\xfe\xff') or b[:5] == b'<?xml' or n.endswith(('.xml', '.config', '.txt', '.log', '.csv', '.html', '.htm', '.json')):
        for enc in ('utf-8-sig', 'utf-16', 'cp1251'):
            try: t = b.decode(enc); break
            except Exception: t = None
        if t is None: return 'text', 'CHECK', 'not decodable'
        if t.lstrip('﻿').lstrip().startswith('<'):
            try:
                ET.fromstring(re.sub(r'^<\?xml[^>]*\?>', '', t.lstrip('﻿').lstrip()).encode('utf-8')); return 'xml', 'OK', 'well-formed'
            except Exception as e: return 'xml', 'CHECK', 'not well-formed: ' + str(e)[:50]
        bad = sum(1 for c in t[:20000] if ord(c) < 9 or 13 < ord(c) < 32)
        return 'text', 'OK' if bad == 0 else 'CHECK', 'readable text' if bad == 0 else '%d control chars' % bad
    if b[:9] == b'\x00\x01\x00\x00\x00\xff\xff\xff\xff':
        return 'dotnet-serialized', 'OK', 'BinaryFormatter header'
    if b[:4] == b'Rar!': return 'rar', 'UNVERIFIED', 'RAR signature present; test with WinRAR/7-Zip'
    if b[:4] == b'%PDF': return 'pdf', 'OK' if b.rstrip().endswith(b'%%EOF') else 'CHECK', 'PDF header and EOF marker'
    if b[:3] == b'\xff\xd8\xff': return 'jpeg', 'OK' if b.rstrip(b'\x00').endswith(b'\xff\xd9') else 'CHECK', 'JPEG start/end markers'
    if b[:2] == b'MZ': return 'exe', 'UNVERIFIED', 'PE signature'
    if b[:8] == b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1': return 'ole-office', 'UNVERIFIED', 'OLE2 signature (doc/xls)'
    if len(b) == 0: return 'empty', 'OK', ''
    return 'unknown', 'UNVERIFIED', 'no known signature'

def find_7z():
    """7z.exe from the 7-Zip installer's registry entry, else from PATH; None when absent."""
    try:
        import winreg
        for view in (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY):
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\7-Zip', 0, winreg.KEY_READ | view) as k:
                    for name in ('Path64', 'Path'):
                        try:
                            p = os.path.join(winreg.QueryValueEx(k, name)[0], '7z.exe')
                            if os.path.exists(p): return p
                        except OSError: pass
            except OSError: pass
    except ImportError: pass
    import shutil
    return shutil.which('7z')

def main(src, out):
    jobs = []
    if os.path.isfile(src): jobs.append((src, os.path.basename(src)))
    else:
        for dp, _, fn in os.walk(src):
            for f in fn:
                if SUFFIX.search(f): jobs.append((os.path.join(dp, f), os.path.relpath(os.path.join(dp, f), src)))
    rows, tally = [], {}
    # Default: the stream most signed files fit.
    hits = [0] * len(KEYS)
    for p, rel in jobs:
        exp = expected(SUFFIX.sub('', p))
        if exp:
            raw = open(p, 'rb').read(16384)
            for i, k in enumerate(KEYS): hits[i] += score(raw, k, exp) == 3
    default = KEYS[hits.index(max(hits))]
    for p, rel in jobs:
        raw = open(p, 'rb').read(); ks = pick(raw, SUFFIX.sub('', os.path.basename(p)), default); dec = decrypt(raw, ks)
        dst = os.path.join(out, SUFFIX.sub('', rel)); os.makedirs(os.path.dirname(dst) or '.', exist_ok=True)
        open(dst, 'wb').write(dec)
        kind, verdict, note = check(os.path.basename(dst), dec)
        if kind in ('rar', 'zip-7z') or (kind == 'unknown' and dec[:6] in (b'7z\xbc\xaf\x27\x1c',)):
            seven = find_7z()
            if seven:
                import subprocess
                r = subprocess.run([seven, 't', dst], capture_output=True, text=True, timeout=1800)
                verdict, note = ('OK', '7-Zip test: all CRC ok') if 'Everything is Ok' in r.stdout else ('CHECK', '7-Zip test failed')
        rows.append([rel, len(raw), min(len(raw), N), kind, verdict, note]); tally[verdict] = tally.get(verdict, 0) + 1
    with open(os.path.join(out, 'jass-decryptor-report.csv'), 'w', newline='', encoding='utf-8-sig') as f:
        w = csv.writer(f); w.writerow(['file', 'size', 'decrypted_bytes', 'kind', 'verdict', 'note']); w.writerows(rows)
    print(len(jobs), 'files ->', out); print(tally)
    for r in rows:
        if r[4] == 'CHECK': print('CHECK:', r[0], '|', r[5])

if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])

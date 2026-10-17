"""Round-trip test without real victim files.
  python selftest.py make <dir>    writes <dir>/expected/* and their encrypted twins <dir>/jass/*.jass
  python selftest.py check <dir> <restored dir>    compares every restored file with expected, byte for byte
The encrypted twins are made with the shipped keystream, so this tests the tools, not the key."""
import io, os, random, sys, zipfile

KS = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'keystream', 'jass_keystream_20000.bin'), 'rb').read()

def files():
    rnd = random.Random(1)
    text = ''.join(rnd.choice('abcdefghij klmnopqrstuvwxyz\n') for _ in range(60000)).encode()
    z = io.BytesIO()
    with zipfile.ZipFile(z, 'w', zipfile.ZIP_DEFLATED) as f:
        f.writestr('a.txt', text)
        f.writestr('b.bin', bytes(rnd.getrandbits(8) for _ in range(30000)))
    xml = b'<?xml version="1.0" encoding="utf-8"?>\n<root>' + b''.join(b'<i n="%d">value</i>' % i for i in range(2000)) + b'</root>'
    return {
        'report.zip': z.getvalue(),
        'Book with spaces .xlsx': z.getvalue(),
        'a.b.c.notes.txt': text,
        'settings.xml': xml,
        'small.txt': b'shorter than the encrypted zone\r\n',
        'zero-filled.config': bytes(1241),
        'no-extension': text[:5000],
    }

def make(d):
    for sub in ('expected', 'jass'):
        os.makedirs(os.path.join(d, sub), exist_ok=True)
    for name, data in files().items():
        open(os.path.join(d, 'expected', name), 'wb').write(data)
        enc = bytes(b ^ KS[i] if i < len(KS) else b for i, b in enumerate(data))
        open(os.path.join(d, 'jass', name + '.jass'), 'wb').write(enc)

def check(d, restored):
    bad = 0
    for name in files():
        p = os.path.join(restored, name)
        ok = os.path.exists(p) and open(p, 'rb').read() == open(os.path.join(d, 'expected', name), 'rb').read()
        print('ok  ' if ok else 'FAIL', name)
        bad += not ok
    sys.exit(1 if bad else 0)

if __name__ == '__main__':
    make(sys.argv[2]) if sys.argv[1] == 'make' else check(sys.argv[2], sys.argv[3])

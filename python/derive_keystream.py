"""Derive the .jass keystream from original/encrypted file pairs (known plaintext).
Usage: python derive_keystream.py <out.bin> <original1> <encrypted1> [<original2> <encrypted2> ...]

Every pair gives keystream = original XOR encrypted for its first min(size, 20000) bytes. Several pairs are combined by
majority vote per position. A pair must be the exact same file before and after encryption: an older copy of the file
gives wrong bytes wherever its content changed. One original of 20000 bytes or more covers the whole stream.
Verify the result on a file with internal checksums (a ZIP, a PNG, an Office document) before trusting it."""
import collections, sys

N = 20000

def main(out, files):
    if len(files) < 2 or len(files) % 2:
        sys.exit(__doc__)
    votes = [collections.Counter() for _ in range(N)]
    for plain, enc in zip(files[0::2], files[1::2]):
        a, b = open(plain, 'rb').read(), open(enc, 'rb').read()
        if len(a) != len(b):
            print('WARNING %s: sizes differ (%d vs %d); not the same file version?' % (plain, len(a), len(b)))
        if a[N:] != b[N:len(a)]:
            print('WARNING %s: bytes after %d differ; not the same file version?' % (plain, N))
        for i in range(min(len(a), len(b), N)):
            votes[i][a[i] ^ b[i]] += 1
    ks = bytearray(N)
    missing, disputed = [], []
    for i, v in enumerate(votes):
        if not v:
            missing.append(i)
            continue
        (best, n), = v.most_common(1)
        ks[i] = best
        if len(v) > 1:
            disputed.append(i)
    open(out, 'wb').write(bytes(ks))
    print('written %s; covered %d of %d positions, disputed %d' % (out, N - len(missing), N, len(disputed)))
    if missing:
        print('NOT COVERED from %d: add a pair with a larger original. The stream is incomplete.' % missing[0])
    if disputed:
        print('disputed positions (check by hand):', disputed[:20], '...' if len(disputed) > 20 else '')

if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2:])

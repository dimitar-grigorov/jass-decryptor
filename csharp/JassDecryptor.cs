// Copyright (c) 2026 Dimitar Grigorov. Licensed under the MIT License (see LICENSE).
//
// Jass Decryptor: restores files hit by the .jass ransomware. The first 20000 bytes of every file are XOR-ed with one fixed
// keystream (embedded resource JassDecryptor.keystream, or jass_keystream_20000.bin placed next to the exe for another victim);
// the rest of the file is untouched. Sources are only read, never changed.
// Build: build.cmd (csc from .NET Framework 4, C# 5). Runs on any Windows with .NET Framework 4.0 or later.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows.Forms;
using System.Xml;
using Microsoft.Win32;

[assembly: System.Reflection.AssemblyTitle("Jass Decryptor")]
[assembly: System.Reflection.AssemblyProduct("Jass Decryptor")]
[assembly: System.Reflection.AssemblyCopyright("Copyright © 2026 Dimitar Grigorov")]
[assembly: System.Reflection.AssemblyVersion("1.2.0.0")]

namespace JassDecryptor
{
    class Key
    {
        public string Name; public byte[] K;
    }

    // One key per infected machine; each file gets the one that fits.
    static class Keystream
    {
        public const int N = 20000;
        public const string FileName = "jass_keystream_20000.bin";
        static readonly string[][] BuiltIn =
        {
            new[] { "JassDecryptor.keystream", "ffff0997f3ac60f55261adda046f2b264c6d2619bacca767d1e4b3a1c3d1cb3d", "built-in 1" },
            new[] { "JassDecryptor.keystream2", "c58faba9452f3323c58bf75af38651c7b029681c0385509fe0ac5ad423e9dde5", "built-in 2" },
        };
        public static readonly List<Key> All = Load();
        // For files whose format cannot tell; set by Preflight.
        public static Key Default = All[0];

        static List<Key> Load()
        {
            var keys = new List<Key>();
            // A key file next to the exe is tried first.
            string ext = Path.Combine(Path.GetDirectoryName(Application.ExecutablePath), FileName);
            if (File.Exists(ext))
            {
                var e = File.ReadAllBytes(ext);
                if (e.Length != N) throw new InvalidDataException(FileName + " must be exactly " + N + " bytes.");
                keys.Add(new Key { Name = FileName, K = e });
            }
            foreach (var b in BuiltIn)
                using (var s = typeof(Keystream).Assembly.GetManifestResourceStream(b[0]))
                {
                    var k = new byte[N];
                    if (s == null || Util.ReadFull(s, k, 0, N) != N || Util.Hex(SHA256.Create().ComputeHash(k)) != b[1])
                        throw new InvalidDataException("The built-in key is damaged.");
                    keys.Add(new Key { Name = b[2], K = k });
                }
            return keys;
        }
    }

    static class Util
    {
        public static string Hex(byte[] b)
        {
            var sb = new StringBuilder();
            foreach (var x in b) sb.Append(x.ToString("x2"));
            return sb.ToString();
        }

        static readonly uint[] CrcTable = MakeCrcTable();
        static uint[] MakeCrcTable()
        {
            var t = new uint[256];
            for (uint i = 0; i < 256; i++)
            {
                uint c = i;
                for (int k = 0; k < 8; k++) c = (c & 1) != 0 ? 0xEDB88320u ^ (c >> 1) : c >> 1;
                t[i] = c;
            }
            return t;
        }
        public static uint Crc32(uint crc, byte[] b, int off, int len)
        {
            crc = ~crc;
            for (int i = off; i < off + len; i++) crc = CrcTable[(crc ^ b[i]) & 0xFF] ^ (crc >> 8);
            return ~crc;
        }

        public static int ReadFull(Stream s, byte[] b, int off, int len)
        {
            int r = 0, n;
            while (r < len && (n = s.Read(b, off + r, len - r)) > 0) r += n;
            return r;
        }

        public static string Size(long n)
        {
            if (n < 1024) return n + " B";
            if (n < 1024 * 1024) return (n / 1024.0).ToString("0.0") + " KB";
            if (n < 1024L * 1024 * 1024) return (n / 1048576.0).ToString("0.0") + " MB";
            return (n / 1073741824.0).ToString("0.00") + " GB";
        }

        public static ushort U16(byte[] b, int o) { return (ushort)(b[o] | b[o + 1] << 8); }
        public static uint U32(byte[] b, int o) { return (uint)(b[o] | b[o + 1] << 8 | b[o + 2] << 16 | b[o + 3] << 24); }
        public static uint U32BE(byte[] b, int o) { return (uint)(b[o] << 24 | b[o + 1] << 16 | b[o + 2] << 8 | b[o + 3]); }

        public static bool StartsWith(byte[] b, int len, params byte[] sig)
        {
            if (len < sig.Length) return false;
            for (int i = 0; i < sig.Length; i++) if (b[i] != sig[i]) return false;
            return true;
        }
    }

    // Read-only view of a .jass file that yields the decrypted bytes; seekable, so format checks and copying share it.
    class JassStream : Stream
    {
        readonly FileStream f;
        readonly byte[] key;
        // null key: plain copy (even number of .jass layers).
        public JassStream(string path, byte[] key)
        {
            // FileShare.Read: a file open for writing elsewhere (e.g. a live .mdf) fails here and is reported as locked.
            f = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 16);
            this.key = key;
        }
        public override int Read(byte[] buffer, int offset, int count)
        {
            long pos = f.Position;
            int n = f.Read(buffer, offset, count);
            if (key != null)
                for (int i = 0; i < n && pos + i < Keystream.N; i++) buffer[offset + i] ^= key[pos + i];
            return n;
        }
        public override bool CanRead { get { return true; } }
        public override bool CanSeek { get { return true; } }
        public override bool CanWrite { get { return false; } }
        public override long Length { get { return f.Length; } }
        public override long Position { get { return f.Position; } set { f.Position = value; } }
        public override long Seek(long offset, SeekOrigin origin) { return f.Seek(offset, origin); }
        public override void Flush() { }
        public override void SetLength(long value) { throw new NotSupportedException(); }
        public override void Write(byte[] buffer, int offset, int count) { throw new NotSupportedException(); }
        protected override void Dispose(bool disposing) { if (disposing) f.Dispose(); base.Dispose(disposing); }
    }

    class SubStream : Stream
    {
        readonly Stream s; readonly long start, len; long pos;
        public SubStream(Stream s, long start, long len) { this.s = s; this.start = start; this.len = len; }
        public override int Read(byte[] buffer, int offset, int count)
        {
            if (pos >= len) return 0;
            s.Position = start + pos;
            int n = s.Read(buffer, offset, (int)Math.Min(count, len - pos));
            pos += n;
            return n;
        }
        public override bool CanRead { get { return true; } }
        public override bool CanSeek { get { return false; } }
        public override bool CanWrite { get { return false; } }
        public override long Length { get { return len; } }
        public override long Position { get { return pos; } set { throw new NotSupportedException(); } }
        public override long Seek(long o, SeekOrigin r) { throw new NotSupportedException(); }
        public override void Flush() { }
        public override void SetLength(long v) { throw new NotSupportedException(); }
        public override void Write(byte[] b, int o, int c) { throw new NotSupportedException(); }
    }

    enum Verdict { OK, UNVERIFIED, CHECK }

    class Check
    {
        public string Kind; public Verdict Verdict; public string Note;
        public Check(string kind, Verdict v, string note) { Kind = kind; Verdict = v; Note = note; }
    }

    static class Formats
    {
        static readonly string[] ZipExt = { ".zip", ".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".odt", ".ods", ".odp", ".jar", ".apk", ".epub", ".vsdx" };
        static readonly string[] XmlExt = { ".xml", ".config", ".xaml", ".resx", ".xsd", ".xsl", ".xslt", ".csproj", ".manifest", ".rdl", ".svg" };
        static readonly string[] TextExt = { ".txt", ".log", ".csv", ".ini", ".json", ".htm", ".html", ".sql", ".bat", ".cmd", ".ps1", ".md", ".inf", ".reg" };
        static readonly string[] OleExt = { ".doc", ".xls", ".ppt", ".msg", ".vsd", ".pub" };

        // Kind the extension promises; null when the extension says nothing.
        public static string Expected(string name)
        {
            string e = Path.GetExtension(name).ToLowerInvariant();
            if (Array.IndexOf(ZipExt, e) >= 0) return "zip";
            if (Array.IndexOf(OleExt, e) >= 0) return "ole";
            if (Array.IndexOf(XmlExt, e) >= 0) return "xml";
            switch (e)
            {
                case ".png": return "png";
                case ".jpg": case ".jpeg": return "jpeg";
                case ".pdf": return "pdf";
                case ".gif": return "gif";
                case ".bmp": return "bmp";
                case ".rar": return "rar";
                case ".7z": return "7z";
                case ".mdb": case ".accdb": return "access";
                case ".bak": return "sql-bak";
                case ".mdf": case ".ndf": case ".ldf": return "sql-data";
                case ".exe": case ".dll": return "pe";
            }
            return null;
        }

        public static string Sniff(byte[] h, int n)
        {
            if (Util.StartsWith(h, n, 0x50, 0x4B, 0x03, 0x04) || Util.StartsWith(h, n, 0x50, 0x4B, 0x05, 0x06)) return "zip";
            if (Util.StartsWith(h, n, 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A)) return "png";
            if (Util.StartsWith(h, n, 0xFF, 0xD8, 0xFF)) return "jpeg";
            if (Util.StartsWith(h, n, 0x25, 0x50, 0x44, 0x46)) return "pdf";
            if (Util.StartsWith(h, n, 0x47, 0x49, 0x46, 0x38)) return "gif";
            if (Util.StartsWith(h, n, 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07)) return "rar";
            if (Util.StartsWith(h, n, 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C)) return "7z";
            if (Util.StartsWith(h, n, 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1)) return "ole";
            if (Util.StartsWith(h, n, 0x54, 0x41, 0x50, 0x45)) return "sql-bak";
            if (n >= 19 && (Encoding.ASCII.GetString(h, 4, 15) == "Standard Jet DB" || Encoding.ASCII.GetString(h, 4, 15) == "Standard ACE DB")) return "access";
            if (Util.StartsWith(h, n, 0x00, 0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF)) return "dotnet";
            if (n >= 8192 && h[0] == 1 && h[1] == 0x0F) return "sql-data";
            if (Util.StartsWith(h, n, 0x4D, 0x5A)) return "pe";
            if (Util.StartsWith(h, n, 0x42, 0x4D) && n >= 6) return "bmp";
            if (LooksXml(h, n)) return "xml";
            return null;
        }

        static bool LooksXml(byte[] h, int n)
        {
            int i = 0;
            if (Util.StartsWith(h, n, 0xEF, 0xBB, 0xBF)) i = 3;
            else if (Util.StartsWith(h, n, 0xFF, 0xFE) || Util.StartsWith(h, n, 0xFE, 0xFF))
            {
                // UTF-16: first non-space character must be '<'.
                for (int j = 2; j + 1 < n; j += 2)
                {
                    char c = h[0] == 0xFF ? (char)(h[j] | h[j + 1] << 8) : (char)(h[j] << 8 | h[j + 1]);
                    if (!char.IsWhiteSpace(c)) return c == '<';
                }
                return false;
            }
            while (i < n && (h[i] == ' ' || h[i] == '\t' || h[i] == '\r' || h[i] == '\n')) i++;
            return i < n && h[i] == '<';
        }

        // Format check of the decrypted content. h/n is the decrypted head (up to 64 KB).
        public static Check Run(string name, JassStream s, byte[] h, int n)
        {
            long len = s.Length;
            if (len == 0) return new Check("empty", Verdict.OK, "empty file");
            bool allZero = true;
            for (int i = 0; i < n && allZero; i++) if (h[i] != 0) allZero = false;
            if (allZero && len <= n) return new Check("zeros", Verdict.UNVERIFIED, "all zeros, like the original");

            string exp = Expected(name), kind = Sniff(h, n);
            string e = Path.GetExtension(name).ToLowerInvariant();
            if (kind == null && Array.IndexOf(TextExt, e) >= 0) kind = "text";
            if (kind == null && exp == "xml") kind = "text";
            if (exp != null && kind != exp && !(exp == "xml" && kind == "text") && !(exp == "ole" && kind == "zip"))
                return new Check(kind ?? "unknown", Verdict.CHECK, "extension says " + exp + ", content is " + (kind ?? "unknown"));

            try
            {
                switch (kind)
                {
                    case "zip": return Zip(s, len);
                    case "png": return Png(s, len);
                    case "jpeg": return Jpeg(h, n);
                    case "pdf":
                        return Regex.IsMatch(Encoding.ASCII.GetString(h, 0, n), @"\d+\s+\d+\s+obj") || len < 2000
                            ? new Check("pdf", Verdict.OK, "header and objects at the start")
                            : new Check("pdf", Verdict.CHECK, "no PDF objects at the start");
                    case "gif": return new Check("gif", Verdict.OK, "GIF header");
                    case "bmp": return Util.U32(h, 2) == len ? new Check("bmp", Verdict.OK, "size in header matches") : new Check("bmp", Verdict.CHECK, "size in header does not match");
                    case "rar": return new Check("rar", Verdict.UNVERIFIED, "RAR header; full test needs 7-Zip");
                    case "7z": return new Check("7z", Verdict.UNVERIFIED, "7z header; full test needs 7-Zip");
                    case "ole":
                        return n >= 32 && h[28] == 0xFE && h[29] == 0xFF && (h[30] == 9 || h[30] == 12)
                            ? new Check("ole", Verdict.OK, "OLE header (doc/xls/msg); open it to be sure")
                            : new Check("ole", Verdict.CHECK, "invalid OLE header");
                    case "sql-bak":
                        {
                            ushort x = 0;
                            for (int i = 0; i < 50; i += 2) x ^= Util.U16(h, i);
                            return n >= 52 && x == Util.U16(h, 50)
                                ? new Check("sql-bak", Verdict.OK, "MTF header; full check: RESTORE VERIFYONLY")
                                : new Check("sql-bak", Verdict.CHECK, "MTF checksum does not match");
                        }
                    case "sql-data": return new Check("sql-data", Verdict.OK, "header page; full check: attach + DBCC CHECKDB");
                    case "access": return new Check("access", Verdict.OK, "Jet/ACE header");
                    case "dotnet":
                        {
                            s.Position = len - 1;
                            return s.ReadByte() == 0x0B ? new Check("dotnet", Verdict.OK, ".NET serialization, start and end") : new Check("dotnet", Verdict.CHECK, ".NET serialization without end");
                        }
                    case "pe":
                        {
                            int pe = n >= 64 ? (int)Util.U32(h, 60) : -1;
                            return pe > 0 && pe + 4 <= n && h[pe] == 'P' && h[pe + 1] == 'E' && h[pe + 2] == 0 && h[pe + 3] == 0
                                ? new Check("pe", Verdict.OK, "PE header") : new Check("pe", Verdict.CHECK, "MZ without PE header");
                        }
                    case "xml": return Xml(s, len);
                    case "text": return Text(h, n);
                }
            }
            catch (Exception ex) { return new Check(kind, Verdict.CHECK, "check failed: " + ex.Message); }
            return new Check("unknown", Verdict.UNVERIFIED, "unknown format");
        }

        // Verifies CRC32 of every entry whose data lies (partly) in the decrypted zone; the rest of the file was never encrypted.
        static Check Zip(Stream s, long len)
        {
            int tl = (int)Math.Min(len, 65557);
            var tail = new byte[tl];
            s.Position = len - tl;
            Util.ReadFull(s, tail, 0, tl);
            int eocd = -1;
            for (int i = tl - 22; i >= 0; i--) if (tail[i] == 0x50 && tail[i + 1] == 0x4B && tail[i + 2] == 5 && tail[i + 3] == 6) { eocd = i; break; }
            if (eocd < 0) return new Check("zip", Verdict.CHECK, "no central directory");
            uint cdSize = Util.U32(tail, eocd + 12), cdOff = Util.U32(tail, eocd + 16);
            if (cdOff == 0xFFFFFFFF || cdSize > 256 * 1024 * 1024) return new Check("zip", Verdict.UNVERIFIED, "ZIP64; header only");
            var cd = new byte[cdSize];
            s.Position = cdOff;
            if (Util.ReadFull(s, cd, 0, (int)cdSize) != cdSize) return new Check("zip", Verdict.CHECK, "truncated central directory");
            int checkedN = 0, skipped = 0;
            var buf = new byte[1 << 16];
            for (int p = 0; p + 46 <= cdSize; )
            {
                if (Util.U32(cd, p) != 0x02014B50) return new Check("zip", Verdict.CHECK, "damaged central directory");
                ushort flags = Util.U16(cd, p + 8), method = Util.U16(cd, p + 10);
                uint crc = Util.U32(cd, p + 16), comp = Util.U32(cd, p + 20), lho = Util.U32(cd, p + 42);
                int nl = Util.U16(cd, p + 28), el = Util.U16(cd, p + 30), cl = Util.U16(cd, p + 32);
                string ename = Encoding.UTF8.GetString(cd, p + 46, nl);
                p += 46 + nl + el + cl;
                if (lho >= Keystream.N) continue;
                var lh = new byte[30];
                s.Position = lho;
                if (Util.ReadFull(s, lh, 0, 30) != 30 || Util.U32(lh, 0) != 0x04034B50) return new Check("zip", Verdict.CHECK, "bad local header: " + ename);
                long data = lho + 30 + Util.U16(lh, 26) + Util.U16(lh, 28);
                if ((flags & 1) != 0 || (method != 0 && method != 8)) { skipped++; continue; }
                Stream src = new SubStream(s, data, comp);
                if (method == 8) src = new DeflateStream(src, CompressionMode.Decompress);
                uint c = 0;
                int r;
                try { while ((r = src.Read(buf, 0, buf.Length)) > 0) c = Util.Crc32(c, buf, 0, r); }
                catch (InvalidDataException) { return new Check("zip", Verdict.CHECK, "bad compressed data: " + ename); }
                if (c != crc) return new Check("zip", Verdict.CHECK, "CRC32 mismatch: " + ename);
                checkedN++;
            }
            if (checkedN == 0) return new Check("zip", Verdict.UNVERIFIED, skipped > 0 ? "entries are password-protected or use an unknown method" : "no entries to check");
            return new Check("zip", Verdict.OK, "CRC32 OK, entries checked: " + checkedN);
        }

        static Check Png(Stream s, long len)
        {
            long p = 8;
            var hd = new byte[8];
            while (p < Keystream.N && p + 12 <= len)
            {
                s.Position = p;
                Util.ReadFull(s, hd, 0, 8);
                uint n = Util.U32BE(hd, 0);
                if (n > 64 * 1024 * 1024 || p + 12 + n > len) return new Check("png", Verdict.CHECK, "bad chunk at " + p);
                var d = new byte[n + 4];
                Util.ReadFull(s, d, 0, (int)n + 4);
                uint c = Util.Crc32(Util.Crc32(0, hd, 4, 4), d, 0, (int)n);
                if (c != Util.U32BE(d, (int)n)) return new Check("png", Verdict.CHECK, "chunk CRC mismatch at " + p);
                if (Encoding.ASCII.GetString(hd, 4, 4) == "IEND") break;
                p += 12 + n;
            }
            return new Check("png", Verdict.OK, "chunk CRC32s match");
        }

        static Check Jpeg(byte[] h, int n)
        {
            int p = 2;
            while (p + 4 <= n)
            {
                if (h[p] != 0xFF) return new Check("jpeg", Verdict.CHECK, "bad marker at " + p);
                if (h[p + 1] == 0xDA) return new Check("jpeg", Verdict.OK, "markers up to the image data are valid");
                p += 2 + (h[p + 2] << 8 | h[p + 3]);
            }
            return new Check("jpeg", Verdict.OK, "markers at the start are valid");
        }

        static Check Xml(Stream s, long len)
        {
            if (len > 64L * 1024 * 1024) return new Check("xml", Verdict.UNVERIFIED, "large XML; header only");
            s.Position = 0;
            try
            {
                // A TextReader ignores the declared encoding: .NET apps often write encoding="utf-16" into UTF-8 files.
                using (var r = XmlReader.Create(new StreamReader(s, Encoding.UTF8, true), new XmlReaderSettings { DtdProcessing = DtdProcessing.Ignore }))
                    while (r.Read()) { }
                return new Check("xml", Verdict.OK, "well-formed XML");
            }
            catch (XmlException ex) { return new Check("xml", Verdict.CHECK, "invalid XML: " + ex.Message); }
        }

        static Check Text(byte[] h, int n)
        {
            string t;
            if (Util.StartsWith(h, n, 0xFF, 0xFE)) t = Encoding.Unicode.GetString(h, 2, (n - 2) & ~1);
            else if (Util.StartsWith(h, n, 0xFE, 0xFF)) t = Encoding.BigEndianUnicode.GetString(h, 2, (n - 2) & ~1);
            else t = Encoding.GetEncoding(1251).GetString(h, 0, Math.Min(n, Keystream.N));
            int bad = 0;
            foreach (char c in t) if (c < 9 || (c > 13 && c < 32 && c != 26)) bad++;
            return bad == 0 ? new Check("text", Verdict.OK, "readable text") : new Check("text", Verdict.CHECK, bad + " control characters");
        }
    }

    enum Action { Restored, AlreadySame, SavedBeside, Replaced, Skipped, Locked, NoSpace, Error, Cancelled }

    enum Conflict { Beside, Replace, Skip }

    class Result
    {
        public string Source, Target, Kind = "", Note = "";
        public long Size;
        public Action Action;
        public Verdict Verdict = Verdict.UNVERIFIED;

        public bool IsProblem
        {
            get { return Verdict == Verdict.CHECK || Action == Action.Error || Action == Action.Locked || Action == Action.NoSpace; }
        }
    }

    static class Engine
    {
        static readonly Regex Suffix = new Regex(@"\.jass(\s.*)?$", RegexOptions.IgnoreCase);

        public static bool IsJass(string path) { return Suffix.IsMatch(Path.GetFileName(path)); }

        public static List<string> Collect(string path, List<string> errors)
        {
            var list = new List<string>();
            if (File.Exists(path)) { if (IsJass(path)) list.Add(path); return list; }
            var stack = new Stack<string>();
            stack.Push(path);
            while (stack.Count > 0)
            {
                string d = stack.Pop();
                try
                {
                    foreach (var f in Directory.GetFiles(d)) if (IsJass(f)) list.Add(f);
                    foreach (var sd in Directory.GetDirectories(d))
                        if ((File.GetAttributes(sd) & FileAttributes.ReparsePoint) == 0) stack.Push(sd);
                }
                catch (Exception ex) { errors.Add(d + ": " + ex.Message); }
            }
            list.Sort(StringComparer.OrdinalIgnoreCase);
            return list;
        }

        // Strips every .jass layer. XOR applied twice cancels out, so an even number of layers means plain content.
        public static string BaseName(string name, out int layers)
        {
            layers = 0;
            while (Suffix.IsMatch(name)) { name = Suffix.Replace(name, ""); layers++; }
            return name;
        }

        static int ReadHead(JassStream s, byte[] h)
        {
            s.Position = 0;
            return Util.ReadFull(s, h, 0, h.Length);
        }

        // Sample files must match their signature with some key; the best key becomes the default.
        public static string Preflight(List<string> files, out int tested, out int passed)
        {
            tested = 0; passed = 0;
            var keys = Keystream.All;
            var hits = new int[keys.Count];
            var raw = new byte[16384]; var h = new byte[16384];
            var bad = new List<string>();
            int step = Math.Max(1, files.Count / 400);
            for (int i = 0; i < files.Count && tested < 40; i += step)
            {
                int layers;
                string bn = BaseName(Path.GetFileName(files[i]), out layers);
                string exp = Formats.Expected(bn);
                if (exp == null || layers % 2 == 0) continue;
                try
                {
                    int n;
                    using (var f = new FileStream(files[i], FileMode.Open, FileAccess.Read, FileShare.Read))
                    {
                        if (f.Length < 64) continue;
                        n = Util.ReadFull(f, raw, 0, raw.Length);
                    }
                    // An all-zero original says nothing about the format.
                    if (keys.Exists(k => Decrypt(raw, n, k.K, h) && Array.TrueForAll(h, b => b == 0))) continue;
                    tested++;
                    bool any = false;
                    for (int k = 0; k < keys.Count; k++)
                        if (Fits(raw, n, keys[k].K, exp, h)) { hits[k]++; any = true; }
                    if (any) passed++;
                    else bad.Add(Path.GetFileName(files[i]));
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
            int best = 0;
            for (int k = 1; k < keys.Count; k++) if (hits[k] > hits[best]) best = k;
            Keystream.Default = keys[best];
            return bad.Count == 0 ? "" : string.Join(", ", bad.GetRange(0, Math.Min(5, bad.Count)).ToArray());
        }

        static bool Decrypt(byte[] raw, int n, byte[] key, byte[] h)
        {
            Array.Clear(h, 0, h.Length);
            for (int j = 0; j < n; j++) h[j] = j < Keystream.N ? (byte)(raw[j] ^ key[j]) : raw[j];
            return true;
        }

        static bool Fits(byte[] raw, int n, byte[] key, string exp, byte[] h)
        {
            Decrypt(raw, n, key, h);
            string k = Formats.Sniff(h, n);
            return k == exp || (exp == "ole" && k == "zip");
        }

        // Best key by signature, then all zeros, then plain text; ties keep the default.
        static Key PickKey(string path, string name)
        {
            if (Keystream.All.Count == 1) return Keystream.Default;
            string exp = Formats.Expected(name);
            var raw = new byte[16384]; var h = new byte[16384];
            int n;
            using (var f = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read)) n = Util.ReadFull(f, raw, 0, raw.Length);
            Key best = Keystream.Default;
            int top = Score(raw, n, best.K, exp, h);
            foreach (var k in Keystream.All)
            {
                int sc = Score(raw, n, k.K, exp, h);
                if (sc > top) { top = sc; best = k; }
            }
            return best;
        }

        static int Score(byte[] raw, int n, byte[] key, string exp, byte[] h)
        {
            if (n == 0) return 0;
            if (exp != null && Fits(raw, n, key, exp, h)) return 3;
            Decrypt(raw, n, key, h);
            int m = Math.Min(n, Keystream.N), zero = 0, ctl = 0;
            for (int j = 0; j < m; j++)
            {
                if (h[j] == 0) zero++;
                else if (h[j] < 9 || (h[j] > 13 && h[j] < 32 && h[j] != 26)) ctl++;
            }
            if (zero == m) return 2;
            return zero == 0 && ctl == 0 ? 1 : 0;
        }

        public delegate Conflict AskConflict(Result r, string existing);

        public static Result ProcessOne(string src, AskConflict ask, Func<bool> cancelled)
        {
            var r = new Result { Source = src };
            try
            {
                var fi = new FileInfo(src);
                r.Size = fi.Length;
                int layers;
                string bn = BaseName(fi.Name, out layers);
                if (bn.Length == 0) { r.Action = Action.Skipped; r.Note = "no name left after removing .jass"; return r; }
                if (layers > 1) r.Note = layers + " times .jass; ";
                string target = Path.Combine(fi.DirectoryName, bn);
                r.Target = target;
                byte[] key = null;
                if (layers % 2 == 1)
                {
                    var k = PickKey(src, bn);
                    key = k.K;
                    if (k != Keystream.Default) r.Note += "key: " + k.Name + "; ";
                }
                Check c;
                using (var s = new JassStream(src, key))
                {
                    var h = new byte[(int)Math.Min(s.Length, 65536)];
                    int n = ReadHead(s, h);
                    c = Formats.Run(bn, s, h, n);
                    r.Kind = c.Kind; r.Verdict = c.Verdict; r.Note += c.Note;

                    string existing = null;
                    if (File.Exists(target))
                    {
                        if (SameContent(s, target)) { r.Action = Action.AlreadySame; return r; }
                        existing = target;
                        Conflict choice = ask(r, target);
                        if (choice == Conflict.Skip) { r.Action = Action.Skipped; r.Note = "a different file exists; " + r.Note; return r; }
                        if (choice == Conflict.Beside)
                        {
                            for (int i = 1; ; i++)
                            {
                                target = Tagged(existing, i == 1 ? " (recovered)" : " (recovered " + i + ")");
                                if (!File.Exists(target)) break;
                                if (SameContent(s, target)) { r.Target = target; r.Action = Action.AlreadySame; r.Note = Path.GetFileName(target) + "; " + r.Note; return r; }
                            }
                        }
                    }

                    if (!HasSpace(target, s.Length)) { r.Action = Action.NoSpace; return r; }
                    string tmp = target + ".jassdecryptor-partial";
                    if (File.Exists(tmp)) File.Delete(tmp);
                    bool done = false;
                    try
                    {
                        using (var o = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1 << 16))
                        {
                            s.Position = 0;
                            var buf = new byte[1 << 20];
                            int rd;
                            while ((rd = s.Read(buf, 0, buf.Length)) > 0)
                            {
                                if (cancelled()) { r.Action = Action.Cancelled; return r; }
                                o.Write(buf, 0, rd);
                            }
                        }
                        if (existing != null && target == existing)
                        {
                            // Replace keeps the old file under a new name; nothing is deleted.
                            string old = Tagged(existing, " (old)");
                            for (int i = 2; File.Exists(old); i++) old = Tagged(existing, " (old " + i + ")");
                            File.Move(existing, old);
                            File.Move(tmp, target);
                            r.Action = Action.Replaced; r.Note = "old one: " + Path.GetFileName(old) + "; " + r.Note;
                        }
                        else
                        {
                            File.Move(tmp, target);
                            r.Action = existing != null ? Action.SavedBeside : Action.Restored;
                            if (existing != null) r.Note = Path.GetFileName(target) + "; " + r.Note;
                        }
                        r.Target = target;
                        done = true;
                    }
                    finally { if (!done && File.Exists(tmp)) File.Delete(tmp); }
                }
                if (r.Kind == "rar" || r.Kind == "7z") SevenZipTest(r, c.Note);
            }
            catch (IOException ex)
            {
                bool locked = (Marshal.GetHRForException(ex) & 0xFFFF) == 32 || (Marshal.GetHRForException(ex) & 0xFFFF) == 33;
                r.Action = locked ? Action.Locked : Action.Error;
                r.Note = (locked ? "open in another program; " : ex.Message + "; ") + r.Note;
            }
            catch (Exception ex) { r.Action = Action.Error; r.Note = ex.Message + "; " + r.Note; }
            return r;
        }

        static string Tagged(string path, string tag)
        {
            return Path.Combine(Path.GetDirectoryName(path), Path.GetFileNameWithoutExtension(path) + tag + Path.GetExtension(path));
        }

        static bool SameContent(JassStream s, string other)
        {
            using (var o = new FileStream(other, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 1 << 16))
            {
                if (o.Length != s.Length) return false;
                s.Position = 0;
                var a = new byte[1 << 16]; var b = new byte[1 << 16];
                while (true)
                {
                    int n = Util.ReadFull(s, a, 0, a.Length);
                    if (n == 0) return true;
                    if (Util.ReadFull(o, b, 0, n) != n) return false;
                    for (int i = 0; i < n; i++) if (a[i] != b[i]) return false;
                }
            }
        }

        static bool HasSpace(string path, long need)
        {
            try { return new DriveInfo(Path.GetPathRoot(Path.GetFullPath(path))).AvailableFreeSpace > need + 64L * 1024 * 1024; }
            catch (ArgumentException) { return true; }
        }

        // The 7-Zip installer records its folder in the registry; a portable copy can be on PATH.
        static string FindSevenZip()
        {
            foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
                using (var k = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view).OpenSubKey(@"SOFTWARE\7-Zip"))
                {
                    var dir = k == null ? null : (k.GetValue("Path64") ?? k.GetValue("Path")) as string;
                    if (dir != null && File.Exists(Path.Combine(dir, "7z.exe"))) return Path.Combine(dir, "7z.exe");
                }
            foreach (var dir in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(';'))
            {
                try { string p = Path.Combine(dir.Trim(), "7z.exe"); if (File.Exists(p)) return p; }
                catch (ArgumentException) { }
            }
            return null;
        }

        static void SevenZipTest(Result r, string headerNote)
        {
            string seven = FindSevenZip();
            if (seven == null) return;
            var psi = new ProcessStartInfo(seven, "t \"" + r.Target + "\" -p-") { UseShellExecute = false, RedirectStandardOutput = true, CreateNoWindow = true };
            using (var pr = Process.Start(psi))
            {
                bool ok = pr.StandardOutput.ReadToEnd().Contains("Everything is Ok");
                pr.WaitForExit();
                r.Verdict = ok ? Verdict.OK : Verdict.CHECK;
                r.Note = r.Note.Replace(headerNote, ok ? "7-Zip test: all CRCs match" : "7-Zip test failed");
            }
        }

        // Not into the scanned folders: a stray .csv there is easily taken for a restored file.
        public static string WriteReport(List<Result> rows)
        {
            string name = "jassdecryptor-report-" + DateTime.Now.ToString("yyyyMMdd-HHmmss") + ".csv";
            var dirs = new[]
            {
                Path.GetDirectoryName(Application.ExecutablePath),
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                Path.GetTempPath()
            };
            foreach (var d in dirs)
            {
                try
                {
                    string rd = Path.Combine(d, "JassDecryptor-reports");
                    Directory.CreateDirectory(rd);
                    string p = Path.Combine(rd, name);
                    for (int i = 2; File.Exists(p); i++) p = Path.Combine(rd, Path.GetFileNameWithoutExtension(name) + "-" + i + ".csv");
                    using (var w = new StreamWriter(p, false, new UTF8Encoding(true)))
                    {
                        w.WriteLine("source;target;size;kind;action;verdict;note");
                        foreach (var r in rows)
                            w.WriteLine(string.Join(";", new[] { Q(r.Source), Q(r.Target), r.Size.ToString(), r.Kind, r.Action.ToString(), r.Verdict.ToString(), Q(r.Note) }));
                    }
                    return p;
                }
                catch (Exception) { }
            }
            return null;
        }

        static string Q(string s) { return "\"" + (s ?? "").Replace("\"", "\"\"") + "\""; }

        public static string ActionText(Action a)
        {
            switch (a)
            {
                case Action.Restored: return "Restored";
                case Action.AlreadySame: return "Already there";
                case Action.SavedBeside: return "Saved beside";
                case Action.Replaced: return "Replaced";
                case Action.Skipped: return "Skipped";
                case Action.Locked: return "In use";
                case Action.NoSpace: return "Disk full";
                case Action.Cancelled: return "Stopped";
                default: return "Error";
            }
        }
    }

    // Vista+ folder picker; FolderBrowserDialog in .NET Framework is the old tree view.
    static class FolderPicker
    {
        [ComImport, Guid("DC1C5A9C-E88A-4dde-A5A1-60F82A20AEF7")] class FileOpenDialogCo { }

        [ComImport, Guid("42f85136-db7e-439c-85f1-e4075d135fc8"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        interface IFileDialog
        {
            [PreserveSig] int Show(IntPtr parent);
            void SetFileTypes(uint n, IntPtr specs);
            void SetFileTypeIndex(uint i);
            void GetFileTypeIndex(out uint i);
            void Advise(IntPtr sink, out uint cookie);
            void Unadvise(uint cookie);
            void SetOptions(uint fos);
            void GetOptions(out uint fos);
            void SetDefaultFolder(IShellItem si);
            void SetFolder(IShellItem si);
            void GetFolder(out IShellItem si);
            void GetCurrentSelection(out IShellItem si);
            void SetFileName([MarshalAs(UnmanagedType.LPWStr)] string name);
            void GetFileName([MarshalAs(UnmanagedType.LPWStr)] out string name);
            void SetTitle([MarshalAs(UnmanagedType.LPWStr)] string title);
            void SetOkButtonLabel([MarshalAs(UnmanagedType.LPWStr)] string text);
            void SetFileNameLabel([MarshalAs(UnmanagedType.LPWStr)] string label);
            void GetResult(out IShellItem si);
        }

        [ComImport, Guid("43826d1e-e718-42ee-bc55-a1e261c37bfe"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        interface IShellItem
        {
            void BindToHandler(IntPtr pbc, ref Guid bhid, ref Guid riid, out IntPtr ppv);
            void GetParent(out IShellItem si);
            void GetDisplayName(uint sigdn, [MarshalAs(UnmanagedType.LPWStr)] out string name);
        }

        [DllImport("shell32.dll", CharSet = CharSet.Unicode, PreserveSig = false)]
        static extern void SHCreateItemFromParsingName(string path, IntPtr pbc, [MarshalAs(UnmanagedType.LPStruct)] Guid riid, out IShellItem si);

        // Null on cancel; the old dialog on XP.
        public static string Pick(IWin32Window owner, string title, string start)
        {
            IFileDialog d;
            try { d = (IFileDialog)new FileOpenDialogCo(); }
            catch (Exception)
            {
                using (var f = new FolderBrowserDialog { Description = title, SelectedPath = start ?? "" })
                    return f.ShowDialog(owner) == DialogResult.OK ? f.SelectedPath : null;
            }
            try
            {
                d.SetOptions(0x20 | 0x40 | 0x800);   // FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST
                d.SetTitle(title);
                if (start != null && Directory.Exists(start))
                    try { IShellItem si; SHCreateItemFromParsingName(start, IntPtr.Zero, typeof(IShellItem).GUID, out si); d.SetFolder(si); }
                    catch (Exception) { }
                if (d.Show(owner.Handle) != 0) return null;
                IShellItem r; string path;
                d.GetResult(out r);
                r.GetDisplayName(0x80058000, out path);   // SIGDN_FILESYSPATH
                return path;
            }
            finally { Marshal.ReleaseComObject(d); }
        }
    }

    class MainForm : Form
    {
        readonly TextBox pathBox = new TextBox
        {
            Anchor = AnchorStyles.Left | AnchorStyles.Right,
            AutoCompleteMode = AutoCompleteMode.SuggestAppend, AutoCompleteSource = AutoCompleteSource.FileSystem
        };
        readonly Button folderBtn = new Button { Text = "Folder…" };
        readonly Button fileBtn = new Button { Text = "File…" };
        readonly Button startBtn = new Button { Text = "Restore", Enabled = false };
        readonly Button stopBtn = new Button { Text = "Stop", Enabled = false };
        readonly Button reportBtn = new Button { Text = "Open report", Enabled = false };
        readonly CheckBox onlyProblems = new CheckBox { Text = "Problems only", AutoSize = true, Anchor = AnchorStyles.Left };
        readonly ListView list = new ListView { View = View.Details, FullRowSelect = true, Dock = DockStyle.Fill };
        readonly ProgressBar bar = new ProgressBar { Anchor = AnchorStyles.Left | AnchorStyles.Right };
        readonly Label status = new Label { Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft, AutoEllipsis = true };
        readonly List<Result> results = new List<Result>();
        readonly Queue<Result> pending = new Queue<Result>();
        readonly System.Windows.Forms.Timer flush = new System.Windows.Forms.Timer { Interval = 250 };
        List<string> files = new List<string>();
        string root, reportPath;
        volatile bool stop;
        int doneCount, scanGen;
        bool running;
        Conflict? conflictForAll;

        public MainForm()
        {
            Text = "Jass Decryptor   |   Copyright © 2026 Dimitar Grigorov";
            Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath);
            Font = new Font("Segoe UI", 9f);
            AutoScaleMode = AutoScaleMode.None;
            float k;
            using (var g = CreateGraphics()) k = g.DpiX / 96f;
            Func<int, int> px = v => (int)(v * k);
            Width = px(1000); Height = px(640); MinimumSize = new Size(px(700), px(400));
            AllowDrop = true;

            var info = new Label
            {
                Text = "Choose, type or drop a folder or a file here. Each file is restored next to its .jass, which stays unchanged.",
                AutoSize = true, Margin = new Padding(3, 3, 3, px(6))
            };
            foreach (var b in new[] { folderBtn, fileBtn, startBtn, stopBtn, reportBtn })
            {
                b.AutoSize = true; b.MinimumSize = new Size(px(90), 0); b.Padding = new Padding(px(6), px(2), px(6), px(2));
            }
            startBtn.Font = new Font(Font, FontStyle.Bold);
            AcceptButton = startBtn;
            var top = new TableLayoutPanel { Dock = DockStyle.Top, AutoSize = true, ColumnCount = 4, RowCount = 2, Padding = new Padding(px(8), px(8), px(8), 0) };
            top.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            for (int i = 0; i < 3; i++) top.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            top.Controls.Add(info, 0, 0); top.SetColumnSpan(info, 4);
            top.Controls.Add(pathBox, 0, 1); top.Controls.Add(folderBtn, 1, 1); top.Controls.Add(fileBtn, 2, 1); top.Controls.Add(startBtn, 3, 1);

            list.Columns.Add("File", px(360)); list.Columns.Add("Size", px(75), HorizontalAlignment.Right);
            list.Columns.Add("Result", px(150)); list.Columns.Add("Check", px(85)); list.Columns.Add("Note", px(420));
            var mid = new Panel { Dock = DockStyle.Fill, Padding = new Padding(px(8)) };
            mid.Controls.Add(list);

            var bottom = new TableLayoutPanel { Dock = DockStyle.Bottom, AutoSize = true, ColumnCount = 5, Padding = new Padding(px(8), 0, px(8), px(8)) };
            bottom.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, px(200)));
            bottom.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            for (int i = 0; i < 3; i++) bottom.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            bar.Height = px(18);
            bottom.Controls.Add(bar, 0, 0); bottom.Controls.Add(status, 1, 0); bottom.Controls.Add(onlyProblems, 2, 0);
            bottom.Controls.Add(stopBtn, 3, 0); bottom.Controls.Add(reportBtn, 4, 0);

            Controls.Add(mid); Controls.Add(bottom); Controls.Add(top);

            folderBtn.Click += delegate
            {
                Cursor.Current = Cursors.WaitCursor;   // the shell dialog takes a second or two to appear
                string p = FolderPicker.Pick(this, "Folder with .jass files", StartFolder());
                if (p != null) SetRoot(p);
            };
            fileBtn.Click += delegate
            {
                Cursor.Current = Cursors.WaitCursor;
                using (var d = new OpenFileDialog { Filter = ".jass files|*.jass*|All files|*.*", InitialDirectory = StartFolder() ?? "" })
                    if (d.ShowDialog(this) == DialogResult.OK) SetRoot(d.FileName);
            };
            pathBox.TextChanged += delegate { PathEdited(); };
            // Enter applies the typed path instead of pressing AcceptButton.
            pathBox.PreviewKeyDown += (s, e) => { if (e.KeyCode == Keys.Enter) e.IsInputKey = true; };
            pathBox.KeyDown += (s, e) => { if (e.KeyCode == Keys.Enter) { e.SuppressKeyPress = true; ApplyTyped(); } };
            pathBox.Leave += delegate { ApplyTyped(); };
            startBtn.Click += delegate { Start(); };
            stopBtn.Click += delegate { stop = true; stopBtn.Enabled = false; status.Text = "Stopping after the current file…"; };
            reportBtn.Click += delegate { if (reportPath != null) Process.Start("explorer.exe", "/select,\"" + reportPath + "\""); };
            onlyProblems.CheckedChanged += delegate { Refill(); };
            DragEnter += (s, e) => { e.Effect = e.Data.GetDataPresent(DataFormats.FileDrop) && !stopBtn.Enabled ? DragDropEffects.Copy : DragDropEffects.None; };
            DragDrop += (s, e) => { var p = (string[])e.Data.GetData(DataFormats.FileDrop); if (p.Length > 0) SetRoot(p[0]); };
            flush.Tick += delegate { Flush(); };
            FormClosing += (s, e) =>
            {
                if (stopBtn.Enabled && MessageBox.Show(this, "Stop now?", Text, MessageBoxButtons.YesNo) == DialogResult.No) e.Cancel = true;
                else stop = true;
            };
        }

        string StartFolder()
        {
            string p = pathBox.Text.Trim();
            if (File.Exists(p)) p = Path.GetDirectoryName(p);
            return Directory.Exists(p) ? p : null;
        }

        bool IsCurrent(string p)
        {
            return root != null && string.Equals(p.Trim().TrimEnd('\\'), root.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase);
        }

        void PathEdited()
        {
            if (running) return;
            string p = pathBox.Text.Trim();
            bool exists = File.Exists(p) || Directory.Exists(p);
            pathBox.BackColor = exists || p.Length == 0 ? SystemColors.Window : Color.FromArgb(255, 220, 220);
            if (IsCurrent(p)) return;
            startBtn.Enabled = false;
            status.Text = p.Length == 0 ? "" : exists ? "Press Enter to look for .jass files there." : "Path not found.";
        }

        void ApplyTyped()
        {
            string p = pathBox.Text.Trim();
            if (!running && !IsCurrent(p) && (File.Exists(p) || Directory.Exists(p))) SetRoot(p);
        }

        public void SetRoot(string p)
        {
            root = p; pathBox.Text = p;
            list.Items.Clear(); results.Clear(); reportPath = null; reportBtn.Enabled = false;
            status.Text = "Looking for .jass files…";
            startBtn.Enabled = false;
            Cursor = Cursors.AppStarting;
            int gen = ++scanGen;
            var t = new Thread(() =>
            {
                var errors = new List<string>();
                var f = Engine.Collect(p, errors);
                long total = 0;
                foreach (var x in f) try { total += new FileInfo(x).Length; } catch (Exception) { }
                BeginInvoke((MethodInvoker)delegate
                {
                    if (gen != scanGen) return;   // a newer path was chosen meanwhile
                    Cursor = Cursors.Default;
                    files = f;
                    status.Text = f.Count + " .jass files, " + Util.Size(total) + (errors.Count > 0 ? "; folders without access: " + errors.Count : "") +
                        (f.Count > 0 ? ". Press Restore to start." : "");
                    startBtn.Enabled = f.Count > 0 && IsCurrent(pathBox.Text);
                    if (startBtn.Enabled && !pathBox.Focused) startBtn.Focus();
                });
            }) { IsBackground = true };
            t.Start();
        }

        void Start()
        {
            int tested, passed;
            status.Text = "Checking the key…";
            status.Update();
            Cursor.Current = Cursors.WaitCursor;
            string bad = Engine.Preflight(files, out tested, out passed);
            if (tested >= 3 && passed < tested * 0.8)
            {
                MessageBox.Show(this, "The key does not fit: " + passed + " of " + tested + " tested files decrypt correctly (e.g. " + bad + ").\nNothing was written.",
                    Text, MessageBoxButtons.OK, MessageBoxIcon.Error);
                status.Text = "Stopped: the key does not fit (" + passed + "/" + tested + ")";
                return;
            }
            // Small sets are checked file by file anyway.
            if (tested < 3 && files.Count > 20 && MessageBox.Show(this, "The key cannot be checked in advance: too few files of a known format.\nContinue?",
                    Text, MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes)
                return;

            stop = false; doneCount = 0; conflictForAll = null;
            results.Clear(); list.Items.Clear();
            bar.Maximum = files.Count; bar.Value = 0;
            running = true; pathBox.ReadOnly = true;
            startBtn.Enabled = folderBtn.Enabled = fileBtn.Enabled = false; stopBtn.Enabled = true; reportBtn.Enabled = false;
            flush.Start();
            var work = new List<string>(files);
            var t = new Thread(() =>
            {
                foreach (var f in work)
                {
                    if (stop) break;
                    var r = Engine.ProcessOne(f, AskOnUiThread, () => stop);
                    lock (pending) pending.Enqueue(r);
                    Interlocked.Increment(ref doneCount);
                }
                BeginInvoke((MethodInvoker)Finish);
            }) { IsBackground = true };
            t.Start();
        }

        Conflict AskOnUiThread(Result r, string existing)
        {
            if (conflictForAll.HasValue) return conflictForAll.Value;
            return (Conflict)Invoke((Func<Conflict>)delegate { return AskConflictDialog(r, existing); });
        }

        Conflict AskConflictDialog(Result r, string existing)
        {
            float k;
            using (var g = CreateGraphics()) k = g.DpiX / 96f;
            Func<int, int> px = v => (int)(v * k);
            var fi = new FileInfo(existing);
            string name = fi.Name, stem = Path.GetFileNameWithoutExtension(name), ext = Path.GetExtension(name);
            Func<long, string> size = n => Util.Size(n) + " (" + n.ToString("N0") + " bytes)";

            var d = new Form
            {
                Text = "File already exists", FormBorderStyle = FormBorderStyle.FixedDialog, StartPosition = FormStartPosition.CenterParent,
                MinimizeBox = false, MaximizeBox = false, ShowInTaskbar = false, Font = Font, AutoScaleMode = AutoScaleMode.None,
                AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, Padding = new Padding(px(14))
            };
            var t = new TableLayoutPanel { AutoSize = true, ColumnCount = 2 };
            t.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize)); t.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            Func<string, Label> text = s => new Label { Text = s, AutoSize = true, MaximumSize = new Size(px(460), 0), Anchor = AnchorStyles.Left, Margin = new Padding(px(3)) };
            Action<Control, int> wide = (ctl, top) => { ctl.Margin = new Padding(px(3), px(top), px(3), px(3)); t.Controls.Add(ctl); t.SetColumnSpan(ctl, 2); };

            var head = text("\"" + name + "\" already exists and is different.");
            head.Font = new Font(Font, FontStyle.Bold); head.MaximumSize = new Size(px(520), 0);
            wide(head, 0);
            var folder = text(fi.DirectoryName); folder.ForeColor = SystemColors.GrayText; folder.MaximumSize = new Size(px(520), 0);
            wide(folder, 0);
            t.Controls.Add(text("Existing:")); t.Controls.Add(text(size(fi.Length) + ", " + fi.LastWriteTime.ToString("yyyy-MM-dd HH:mm")));
            t.Controls.Add(text("Restored:")); t.Controls.Add(text(size(r.Size)));
            t.Controls[t.Controls.Count - 1].Margin = new Padding(px(3), px(3), px(3), px(12));

            var b1 = new Button { Text = "Keep both", DialogResult = DialogResult.Yes };
            var b2 = new Button { Text = "Replace", DialogResult = DialogResult.No };
            var b3 = new Button { Text = "Skip", DialogResult = DialogResult.Ignore };
            var what = new[]
            {
                "The restored file is saved as \"" + stem + " (recovered)" + ext + "\".",
                "The existing file is renamed to \"" + stem + " (old)" + ext + "\".",
                "Nothing is written."
            };
            var bs = new[] { b1, b2, b3 };
            for (int i = 0; i < 3; i++)
            {
                bs[i].AutoSize = true; bs[i].MinimumSize = new Size(px(120), px(28)); bs[i].Anchor = AnchorStyles.Left | AnchorStyles.Right;
                t.Controls.Add(bs[i]); t.Controls.Add(text(what[i]));
            }
            var all = new CheckBox { Text = "Do the same for all remaining", AutoSize = true };
            wide(all, 12);

            d.Controls.Add(t);
            d.AcceptButton = b1; d.CancelButton = b3;
            var res = d.ShowDialog(this);
            Conflict c = res == DialogResult.No ? Conflict.Replace : res == DialogResult.Ignore ? Conflict.Skip : Conflict.Beside;
            if (res == DialogResult.Cancel) c = Conflict.Skip;
            if (all.Checked) conflictForAll = c;
            return c;
        }

        void Flush()
        {
            var batch = new List<Result>();
            lock (pending) while (pending.Count > 0) batch.Add(pending.Dequeue());
            if (batch.Count > 0)
            {
                list.BeginUpdate();
                foreach (var r in batch) { results.Add(r); if (Show(r)) list.Items.Add(Item(r)); }
                list.EndUpdate();
                if (list.Items.Count > 0) list.EnsureVisible(list.Items.Count - 1);
            }
            bar.Value = Math.Min(bar.Maximum, doneCount);
            status.Text = "Processed " + doneCount + " of " + files.Count;
        }

        bool Show(Result r)
        {
            return !onlyProblems.Checked || !((r.Action == Action.Restored || r.Action == Action.AlreadySame) && r.Verdict == Verdict.OK);
        }

        ListViewItem Item(Result r)
        {
            string rel = r.Source;
            if (!Directory.Exists(root)) rel = Path.GetFileName(rel);
            else if (rel.StartsWith(root, StringComparison.OrdinalIgnoreCase)) rel = rel.Substring(root.Length).TrimStart('\\');
            var it = new ListViewItem(new[] { rel, Util.Size(r.Size), Engine.ActionText(r.Action), r.Verdict.ToString(), r.Note });
            if (r.IsProblem) it.BackColor = Color.FromArgb(255, 220, 220);
            else if (r.Verdict == Verdict.UNVERIFIED || r.Action == Action.SavedBeside || r.Action == Action.Replaced || r.Action == Action.Skipped) it.BackColor = Color.FromArgb(255, 245, 200);
            else if (r.Action == Action.AlreadySame) it.ForeColor = Color.Gray;
            return it;
        }

        void Refill()
        {
            list.BeginUpdate(); list.Items.Clear();
            foreach (var r in results) if (Show(r)) list.Items.Add(Item(r));
            list.EndUpdate();
        }

        void Finish()
        {
            flush.Stop(); Flush();
            reportPath = Engine.WriteReport(results);
            reportBtn.Enabled = reportPath != null;
            running = false; pathBox.ReadOnly = false;
            startBtn.Enabled = folderBtn.Enabled = fileBtn.Enabled = true; stopBtn.Enabled = false;
            var cnt = new Dictionary<string, int>();
            int problems = 0;
            foreach (var r in results)
            {
                string k = Engine.ActionText(r.Action);
                cnt[k] = (cnt.ContainsKey(k) ? cnt[k] : 0) + 1;
                if (r.IsProblem) problems++;
            }
            var sb = new StringBuilder();
            foreach (var kv in cnt) sb.AppendLine(kv.Key + ": " + kv.Value);
            sb.AppendLine("Need a look: " + problems);
            if (reportPath != null) sb.AppendLine().AppendLine("Report: " + reportPath);
            status.Text = (stop ? "Stopped: " : "Done: ") + results.Count + " files, need a look: " + problems;
            MessageBox.Show(this, sb.ToString(), stop ? "Stopped" : "Done", MessageBoxButtons.OK, problems > 0 ? MessageBoxIcon.Warning : MessageBoxIcon.Information);
        }
    }

    static class Program
    {
        [DllImport("kernel32.dll")] static extern bool AttachConsole(int pid);
        [DllImport("kernel32.dll")] static extern bool AllocConsole();
        [DllImport("kernel32.dll")] static extern IntPtr GetStdHandle(int which);
        [DllImport("kernel32.dll")] static extern uint GetFileType(IntPtr h);
        [DllImport("user32.dll")] static extern bool SetProcessDPIAware();

        const string Usage =
            "Jass Decryptor, Copyright (c) 2026 Dimitar Grigorov\n" +
            "Restores .jass files next to themselves; the .jass files are never changed.\n\n" +
            "  JassDecryptor.exe /cli <folder or file> [/conflict:beside|replace|skip] [/force]\n\n" +
            "  /conflict  when a different file with the target name exists:\n" +
            "             beside  = save as \"name (recovered).ext\" (default)\n" +
            "             replace = rename the existing one to \"name (old).ext\", then restore\n" +
            "             skip    = leave it\n" +
            "  /force     continue even if the key check fails\n\n" +
            "Ctrl+C stops after the current file.\n" +
            "Exit code: 0 clean, 1 some files need a look, 2 the key does not fit,\n" +
            "           3 the key cannot be loaded, 4 bad arguments or nothing found.\n" +
            "In cmd.exe use \"start /wait\" to wait for it; batch files wait on their own.";

        [STAThread]
        static int Main(string[] args)
        {
            bool cli = args.Length >= 1 && (args[0].Equals("/cli", StringComparison.OrdinalIgnoreCase) || args[0] == "/?" || args[0] == "-h" || args[0] == "--help");
            // A GUI exe gets no console of its own: keep a redirected stdout (file or pipe), else borrow the
            // caller's console, else open one (Run dialog, shortcut).
            uint outType = GetFileType(GetStdHandle(-11));
            bool redirected = outType == 1 || outType == 3;
            bool ownConsole = cli && !redirected && !AttachConsole(-1) && AllocConsole();
            if (cli)
            {
                // Otherwise Cyrillic names become "?" in a redirected file.
                if (redirected) Console.SetOut(new StreamWriter(Console.OpenStandardOutput(), new UTF8Encoding(false)) { AutoFlush = true });
                int code = CliMain(args);
                if (ownConsole) { Console.Write("\nPress Enter to close."); Console.ReadLine(); }
                return code;
            }
            string keyError = KeystreamError();
            if (keyError != null)
            {
                MessageBox.Show(keyError, "Jass Decryptor", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return 3;
            }
            if (Environment.OSVersion.Version.Major >= 6) SetProcessDPIAware();
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            var f = new MainForm();
            // A file or folder dropped onto JassDecryptor.exe arrives as the first argument.
            if (args.Length == 1) f.Shown += delegate { f.SetRoot(args[0]); };
            Application.Run(f);
            return 0;
        }

        static string KeystreamError()
        {
            try { return Keystream.All.Count > 0 ? null : "?"; }
            catch (TypeInitializationException ex) { return (ex.InnerException ?? ex).Message; }
        }

        static int CliMain(string[] args)
        {
            // The caller's prompt is already printed; start on a fresh line.
            Console.WriteLine();
            bool help = !args[0].Equals("/cli", StringComparison.OrdinalIgnoreCase);
            if (help || args.Length < 2) { Console.WriteLine(Usage); return help ? 0 : 4; }
            Conflict conflict = Conflict.Beside;
            bool force = false;
            for (int i = 2; i < args.Length; i++)
            {
                string a = args[i].ToLowerInvariant();
                if (a == "/conflict:beside") conflict = Conflict.Beside;
                else if (a == "/conflict:replace") conflict = Conflict.Replace;
                else if (a == "/conflict:skip") conflict = Conflict.Skip;
                else if (a == "/force") force = true;
                else { Console.WriteLine("Unknown option: " + args[i] + "\n\n" + Usage); return 4; }
            }
            string keyError = KeystreamError();
            if (keyError != null) { Console.WriteLine(keyError); return 3; }
            return Cli(Path.GetFullPath(args[1].Trim('"')), conflict, force);
        }

        static int Cli(string root, Conflict conflict, bool force)
        {
            var errors = new List<string>();
            var files = Engine.Collect(root, errors);
            foreach (var e in errors) Console.WriteLine("cannot read " + e);
            if (files.Count == 0) { Console.WriteLine("No .jass files in " + root); return 4; }
            int tested, passed;
            string bad = Engine.Preflight(files, out tested, out passed);
            Console.WriteLine(files.Count + (files.Count == 1 ? " .jass file in " : " .jass files in ") + root + "; key: " + Keystream.Default.Name + "; key check: " + passed + " of " + tested);
            if (tested >= 3 && passed < tested * 0.8 && !force)
            {
                Console.WriteLine("The key does not fit (e.g. " + bad + "). Nothing was written.");
                return 2;
            }

            bool stop = false;
            Console.CancelKeyPress += (s, e) => { e.Cancel = true; stop = true; Console.WriteLine("Stopping after the current file..."); };
            var rows = new List<Result>();
            int problems = 0;
            foreach (var f in files)
            {
                if (stop) break;
                var r = Engine.ProcessOne(f, delegate { return conflict; }, () => stop);
                rows.Add(r);
                if (r.IsProblem) problems++;
                string rel = f.StartsWith(root, StringComparison.OrdinalIgnoreCase) && f.Length > root.Length ? f.Substring(root.Length).TrimStart('\\') : Path.GetFileName(f);
                Console.WriteLine("{0,-14} {1,-10} {2}{3}", Engine.ActionText(r.Action), r.Verdict, rel, r.Note.Length > 0 ? "  (" + r.Note.TrimEnd(' ', ';') + ")" : "");
            }

            var cnt = new Dictionary<string, int>();
            foreach (var r in rows) { string k = Engine.ActionText(r.Action); cnt[k] = (cnt.ContainsKey(k) ? cnt[k] : 0) + 1; }
            Console.WriteLine();
            foreach (var kv in cnt) Console.WriteLine(kv.Key + ": " + kv.Value);
            Console.WriteLine("Need a look: " + problems + (stop ? " (stopped, " + (files.Count - rows.Count) + " not processed)" : ""));
            string report = Engine.WriteReport(rows);
            if (report != null) Console.WriteLine("Report: " + report);
            return problems > 0 || stop ? 1 : 0;
        }
    }
}

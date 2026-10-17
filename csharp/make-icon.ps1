# Draws JassDecryptor.ico (green tile with an open padlock) in 16/24/32/48/64/256 px, PNG-compressed entries.
Add-Type -AssemblyName System.Drawing
$sizes = 16, 24, 32, 48, 64, 256
$pngs = foreach ($n in $sizes) {
    $bmp = New-Object Drawing.Bitmap $n, $n
    $g = [Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = 'AntiAlias'; $g.Clear([Drawing.Color]::Transparent)
    $u = $n / 16.0
    # Rounded tile.
    $r = [Math]::Max(2, 3 * $u); $path = New-Object Drawing.Drawing2D.GraphicsPath
    $w = $n - 1
    $path.AddArc(0, 0, 2 * $r, 2 * $r, 180, 90); $path.AddArc($w - 2 * $r, 0, 2 * $r, 2 * $r, 270, 90)
    $path.AddArc($w - 2 * $r, $w - 2 * $r, 2 * $r, 2 * $r, 0, 90); $path.AddArc(0, $w - 2 * $r, 2 * $r, 2 * $r, 90, 90); $path.CloseFigure()
    $brush = New-Object Drawing.Drawing2D.LinearGradientBrush ([Drawing.Point]::new(0, 0)), ([Drawing.Point]::new(0, $n)), ([Drawing.Color]::FromArgb(46, 170, 90)), ([Drawing.Color]::FromArgb(20, 120, 60))
    $g.FillPath($brush, $path)
    # Open shackle: arc lifted and shifted right, left leg free.
    $pen = New-Object Drawing.Pen ([Drawing.Color]::White), ([Math]::Max(1.6, 1.6 * $u))
    $g.DrawArc($pen, 6.2 * $u, 2.2 * $u, 5.6 * $u, 5.6 * $u, 180, 180)
    $g.DrawLine($pen, 11.8 * $u, 5 * $u, 11.8 * $u, 7.6 * $u)
    $g.DrawLine($pen, 6.2 * $u, 5 * $u, 6.2 * $u, 5.8 * $u)
    # Lock body with keyhole.
    $g.FillRectangle([Drawing.Brushes]::White, 3.2 * $u, 7.4 * $u, 9.6 * $u, 6.6 * $u)
    if ($n -ge 24) {
        $kh = New-Object Drawing.SolidBrush ([Drawing.Color]::FromArgb(20, 120, 60))
        $g.FillEllipse($kh, 7 * $u, 9 * $u, 2 * $u, 2 * $u); $g.FillRectangle($kh, 7.6 * $u, 10.4 * $u, 0.8 * $u, 2 * $u)
    }
    $g.Dispose()
    $ms = New-Object IO.MemoryStream; $bmp.Save($ms, [Drawing.Imaging.ImageFormat]::Png); $bmp.Dispose()
    , $ms.ToArray()
}
$out = New-Object IO.MemoryStream; $bw = New-Object IO.BinaryWriter $out
$bw.Write([uint16]0); $bw.Write([uint16]1); $bw.Write([uint16]$sizes.Count)
$offset = 6 + 16 * $sizes.Count
for ($i = 0; $i -lt $sizes.Count; $i++) {
    $s = $sizes[$i] % 256
    $bw.Write([byte]$s); $bw.Write([byte]$s); $bw.Write([byte]0); $bw.Write([byte]0)
    $bw.Write([uint16]1); $bw.Write([uint16]32); $bw.Write([uint32]$pngs[$i].Length); $bw.Write([uint32]$offset)
    $offset += $pngs[$i].Length
}
foreach ($p in $pngs) { $bw.Write($p) }
[IO.File]::WriteAllBytes((Join-Path $PSScriptRoot 'JassDecryptor.ico'), $out.ToArray())

@echo off
rem Builds JassDecryptor.exe with the C# compiler that ships with .NET Framework 4; nothing to install.
cd /d "%~dp0"
"%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /nologo /target:winexe /optimize+ /codepage:65001 ^
  /resource:..\keystream\jass_keystream_20000.bin,JassDecryptor.keystream ^
  /resource:..\keystream\jass_keystream_20000_2.bin,JassDecryptor.keystream2 /win32icon:JassDecryptor.ico ^
  /r:System.Windows.Forms.dll /r:System.Drawing.dll /r:System.Xml.dll ^
  /out:JassDecryptor.exe JassDecryptor.cs

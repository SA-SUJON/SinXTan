# SinXTan

SinXTan is a Windows desktop app that encrypts files and embeds the encrypted container inside lossless PNG, BMP, or TIFF images. It also extracts and verifies containers created by the app.

<p align="center">
  <img src="assets/icons/icon.png" width="96" alt="SinXTan app icon">
</p>

[![Windows](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011-2563eb)](#download)
[![Python](https://img.shields.io/badge/Python-3.12%2B-3776ab)](#run-from-source)
[![License: MIT](https://img.shields.io/badge/License-MIT-16a34a)](LICENSE)

## Features

- Encrypt files, folders, and archives with AES-256-GCM.
- Derive keys from the passphrase with Argon2id and separate encryption and embedding keys with HKDF-SHA256.
- Embed encrypted data using a keyed least-significant-bit (LSB) permutation.
- Extract containers and verify authentication and per-file SHA-256 checksums before saving recovered files.
- Use a desktop interface with drag-and-drop file selection and adjustable embedding depth.

## Supported carrier images

SinXTan accepts and writes lossless **PNG**, **BMP**, and **TIFF** images (including `.tif`). JPEG and lossy WebP are not supported. Keep carrier images unchanged after embedding; resizing, editing, or recompression can corrupt the hidden data.

LSB steganography is not guaranteed to be undetectable. Statistical steganalysis may reveal that an image has been modified. See [SECURITY.md](SECURITY.md) for the implementation notes and limitations.

## Download

Download **SinXTan v1.0.0** from the [GitHub Releases](https://github.com/SA-SUJON/SinXTan/releases/latest) page. The Windows x64 release includes a standalone executable and does not require a separate Python installation.

## Run from source

Requirements: Windows 10 or 11 (64-bit) and Python 3.12 or newer.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python main.py
```

## Build the Windows executable

From the project directory, build with the included PyInstaller spec. It embeds the app icon and applies the Windows packaging settings used for releases.

```powershell
.\.venv\Scripts\pyinstaller.exe --noconfirm --clean SinXTan.spec
```

The executable is written to `dist/SinXTan.exe`.

## Run the test suite

```powershell
.\.venv\Scripts\pytest.exe tests -v
```

## License

SinXTan is released under the MIT License. See [LICENSE](LICENSE).

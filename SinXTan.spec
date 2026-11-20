# -*- mode: python ; coding: utf-8 -*-

import os


a = Analysis(
    [os.path.join(SPECPATH, "main.py")],
    pathex=[],
    binaries=[],
    datas=[
        (os.path.join(SPECPATH, "assets", "icons", "icon.png"), "assets/icons"),
    ],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)

# Qt 6 uses Windows' ICU compatibility DLL. Do not bundle unrelated ICU
# binaries that PyInstaller may discover on the build machine's PATH.
for binary in list(a.binaries):
    if os.path.basename(binary[0]).casefold() in {"icuuc.dll", "icudt78.dll"}:
        a.binaries.remove(binary)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='SinXTan',
    icon=os.path.join(SPECPATH, "assets", "icons", "icon.ico"),
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

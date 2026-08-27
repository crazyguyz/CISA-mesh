# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec for GIAM-SAT Updater (lightweight, ~6-8 MB).
No scapy, pygame, tkinter, cryptography - just HTTP server + urllib + subprocess.
"""

a = Analysis(
    ['updater.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['pkg_resources', 'setuptools', 'jaraco', 'jaraco.text', 'jaraco.context', 'jaraco.functools', 'backports',
              'pip', 'wheel', 'distutils', 'importlib_metadata', 'importlib_resources', 'zipp', 'tomli', 'more_itertools',
              'platformdirs', 'packaging', 'pygments', 'wcwidth', 'elftools', 'tqdm', 'setuptools_scm',
              'PIL', 'numpy', 'pygame', 'matplotlib', 'pandas', 'scipy',
              'scapy', 'scapy.all', 'scapy.layers', 'scapy.layers.all',
              'tkinter', '_tkinter', 'tkinter.ttk', 'tkinter.filedialog',
              'cryptography', 'OpenSSL', 'ssl',
              'pywin', 'win32api', 'win32file', 'win32service', 'win32serviceutil',
              'servicemanager', 'win32event',
              'PyQt5', 'PySide2', 'PySide6',
              'sqlite3', 'xml', 'xml.etree'],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='GiamSatUpdater',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # v5.0.2 windowed - no console flash at boot
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
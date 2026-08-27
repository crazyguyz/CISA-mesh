# -*- mode: python ; coding: utf-8 -*-
import os, sys

# Bundle tcl/tk data so tkinter dialogs (message reply box + config dialog)
# work in the packaged EXE. Fixes 'Can't find a usable init.tcl'.
_tcl_root = os.path.join(sys.base_prefix, 'tcl')
_tcl_datas = []
for _sub in ('tcl8.6', 'tk8.6'):
    _p = os.path.join(_tcl_root, _sub)
    if os.path.isdir(_p):
        _tcl_datas.append((_p, os.path.join('tcl', _sub)))


a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[('agent_version.txt', '.'), ('Sysmon64.exe', '.'), ('sysmon_config.xml', '.')] + _tcl_datas,
    hiddenimports=['win32file'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['pkg_resources', 'setuptools', 'jaraco', 'jaraco.text', 'jaraco.context', 'jaraco.functools', 'backports',
              'pip', 'wheel', 'distutils', 'importlib_metadata', 'importlib_resources', 'zipp', 'tomli', 'more_itertools',
              'platformdirs', 'packaging', 'pygments', 'wcwidth', 'elftools', 'tqdm', 'setuptools_scm',
              'PIL', 'numpy', 'pygame', 'matplotlib', 'pandas', 'scipy'],
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
    name='GiamSatAgent',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir='C:\\ProgramData\\GIAM-SAT\\Agent\\runtime',
    console=False,  # v5.0.2 windowed - no console flash at boot
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

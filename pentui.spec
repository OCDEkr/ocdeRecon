# PyInstaller build spec for a single-binary `pentui` (PROJECT.md §14).
#
#   pip install -e ".[dev]"        # provides pyinstaller
#   pyinstaller pentui.spec        # -> dist/pentui (onefile)
#
# Bundles the declarative tool/workflow manifests (loaded at runtime by path,
# so they must ship as data), Textual's package data + dynamic imports, and the
# SQLCipher native extension used for encrypted engagements.

from PyInstaller.utils.hooks import collect_all, collect_data_files

datas = []
binaries = []
hiddenimports = []

# Packaged YAML manifests: registry/workflow loaders read them from
# `pentui/tools` and `pentui/workflows` relative to the package, so they must
# land at that same relative path inside the bundle.
datas += collect_data_files("pentui", includes=["tools/*.yaml", "workflows/*.yaml"])

# Third-party packages that need their data files and/or have dynamic imports
# PyInstaller can't follow statically.
for _pkg in ("textual", "sqlcipher3"):
    _d, _b, _h = collect_all(_pkg)
    datas += _d
    binaries += _b
    hiddenimports += _h


a = Analysis(
    ["src/pentui/cli.py"],
    pathex=["src"],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="pentui",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
)

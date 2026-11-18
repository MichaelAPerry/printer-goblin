import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files


packaging_dir = Path(SPECPATH)
data = collect_data_files(
    "printer_gremlin",
    include_py_files=True,
    includes=["assets/*.pbm", "assets/*.png", "gui/static/*", "payloads/font_fixed.py"],
)

icon = None
if sys.platform == "win32":
    from PIL import Image

    icon = Path(workpath) / "gremlin.ico"
    icon.parent.mkdir(parents=True, exist_ok=True)
    with Image.open(packaging_dir.parent / "printer_gremlin/assets/gremlin_256.png") as source:
        source.save(icon, format="ICO")

analysis = Analysis([str(packaging_dir / "entry.py")], datas=data)
pyz = PYZ(analysis.pure)

exe = EXE(
    pyz,
    analysis.scripts,
    analysis.binaries,
    analysis.datas,
    name="printer-gremlin",
    console=True,
    icon=str(icon) if icon else None,
    upx=False,
)

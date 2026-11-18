# Build Printer Gremlin

Build on the operating system and architecture you want to distribute for. From the repository root, activate a Python 3.12 virtual environment and run:

```sh
python -m pip install . pyinstaller pillow
python -m PyInstaller --noconfirm --workpath packaging/build --distpath packaging/dist packaging/printer-gremlin.spec
```

The executable is written to `packaging/dist/printer-gremlin` on macOS and Linux, or `packaging/dist/printer-gremlin.exe` on Windows. On Windows, the spec uses Pillow to generate the executable icon during the build. Run the executable without arguments to open the local web GUI.

To smoke-test the macOS or Linux executable, run the commands below. On Windows, replace the executable path with `./packaging/dist/printer-gremlin.exe`.

```sh
./packaging/dist/printer-gremlin --help
./packaging/dist/printer-gremlin preview --format pdf -o packaging/dist/smoke.pdf
./packaging/dist/printer-gremlin preview --format escpos --paper 58 -o packaging/dist/smoke.bin
python -c "from pathlib import Path; assert Path('packaging/dist/smoke.pdf').read_bytes().startswith(b'%PDF'); assert Path('packaging/dist/smoke.bin').stat().st_size > 0"
```

To build the Python wheel and source distribution:

```sh
python -m pip install build
python -m build --outdir packaging/dist
```

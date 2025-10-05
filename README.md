# Aurora Recover

Aurora Recover is a Python-based pre-alpha prototype for scanning and recovering data from storage targets such as local directories, trash bins, disk images, and block devices. It ships with a Tkinter GUI plus a lightweight CLI self-check (`python3 main.py --check`).

## Highlights

- **Target discovery**: lists home directories, trash/recycle folders, mounted volumes, and block devices/partitions (via `/sys/block` on Linux).
- **Multiple scan modes**:
  - *Quick scan*: walks the filesystem tree and indexes files.
  - *Trash scan*: inspects trash/recycle locations.
  - *Deep scan*: performs signature-based carving and optionally enriches results with filesystem metadata (NTFS, FAT/FAT32, EXT2/3/4, APFS/HFS+).
- **Filesystem analyzers**:
  - **NTFS** – parses the MFT, rebuilds paths, recovers resident/non-resident data streams.
  - **FAT/FAT32** – enumerates directories, follows cluster chains, and streams file recovery.
  - **EXT2/3/4** – handles indirect blocks and extents to recover file contents.
  - **APFS/HFS+** – integrates `pyfsapfs` and `pytsk3`; falls back to a simplified catalog format for test fixtures.
- **Signature carving**: a broad, categorised catalog (images, documents, archives, audio, video, executables, databases). All signatures are unchecked by default and can be toggled via the “Filter signatures” dialog.
- **Recovery**: exports original files or carved segments into a destination folder with name sanitisation, collision handling, and filesystem-specific recovery hooks.
- **Dark-themed UI**: device/file-system/signature selectors, progress updates, cancel button, and two result tabs (“File system” and “File carving”).
- **Privilege-aware launcher**: `launch.sh` re-invokes `main.py` through `pkexec` while preserving `DISPLAY`/`XAUTHORITY`; the self-check remains headless-friendly.

## Project Layout

```
.
├── main.py                # CLI / GUI entrypoint
├── launch.sh              # launcher with pkexec elevation
├── data/
│   ├── config.py          # config constants and signature catalog
│   ├── controller.py      # GUI ↔ engine orchestration
│   ├── models.py          # domain models (targets, results, signatures…)
│   ├── scanner.py         # quick/trash/deep scans + filesystem analyzers
│   ├── recovery.py        # recovery helpers for files and carved segments
│   ├── fs/
│   │   ├── apple.py       # APFS/HFS+ analyzer (pyfsapfs / pytsk3)
│   │   ├── ext.py         # EXT2/3/4 analyzer
│   │   ├── fat.py         # FAT/FAT32 analyzer
│   │   └── ntfs.py        # NTFS analyzer
│   ├── ui.py              # Tkinter interface (dark theme)
│   ├── utils.py           # shared helpers (threading, formatting…)
│   └── tests/             # unittest suite + synthetic disk builders
└── README.md
```

## Requirements

- Python 3.10+
- Optional for Apple support: `pyfsapfs`, `pytsk3` (bundled inside the repo’s virtualenv)
- A graphical environment for the Tk UI (X11, Wayland, etc.)

## Quick Start

1. (Optional) Create/activate a virtualenv:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

2. Install optional dependencies (already baked into the bundled venv):
   ```bash
   pip install libfsapfs-python pytsk3
   ```

3. Launch the GUI:
   ```bash
   ./launch.sh
   ```
   If elevation is required, a `pkexec` prompt will appear.

4. Run a headless self-check:
   ```bash
   python3 main.py --check
   ```

## Using the GUI

1. **Pick a source** – select a previously discovered entry or load a disk image.
2. **Choose a filesystem parser (optional)** – if you need NTFS/FAT/EXT/Apple metadata, set the filter via “Select filesystem…”.
3. **Select signatures** – open “Filter signatures…” and tick the formats you want to carve; signatures are grouped by category.
4. **Run the scan** – choose Quick/Trash/Deep and monitor progress; operations are cancellable.
5. **Inspect results** – filesystem hits live under the “File system” tab, carved segments under “File carving”. If a filesystem analyzer ran, you’ll see the recoverable entries there.
6. **Recover** – highlight an item and press “Recover selection” to export; filesystem-aware handlers (NTFS, FAT, EXT, Apple) are invoked automatically.

## Automated Checks

```bash
python3 -m unittest        # unit tests
python3 -m compileall data # syntax/bytecode check
```

## Caveats / TODO

- **APFS/HFS+ real-world images** – the current analyzers work on test fixtures; complex cases (multiple volumes, encryption, snapshots) still need in-field testing and might require password/unlock workflows.
- **Header-only signatures** – many formats rely on headers only; carving may overrun until another signature is found. Tight validation (e.g., ZIP central directory parsing for DOCX/XLSX) would reduce false positives.
- **Performance** – deep scans on large APFS/EXT/HFS images can be slow; caching and multi-threaded carving are future goals.
- **UI improvements** – previews, richer metadata panes, persistent sessions, and reporting/export features would enhance UX.

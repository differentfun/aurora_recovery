"""Configuration constants for the Aurora Recover utility."""
from __future__ import annotations

from pathlib import Path

from .models import FileSignature

APP_NAME = "Aurora Recover"
APP_VERSION = "0.1.0"

# Default chunk size used while carving binary images. The value is intentionally
# conservative to keep memory usage reasonable in Python without external deps.
DEFAULT_SCAN_CHUNK_SIZE = 2 * 1024 * 1024  # 2 MiB
MAX_PREVIEW_BYTES = 256

IMAGES_SIGNATURES = [
    FileSignature("JPEG Image", ".jpg", bytes.fromhex("FFD8FF"), bytes.fromhex("FFD9"), category="Images"),
    FileSignature("PNG Image", ".png", b"\x89PNG\r\n\x1a\n", bytes.fromhex("49454E44AE426082"), category="Images"),
    FileSignature("GIF Image", ".gif", b"GIF8", b";", category="Images"),
    FileSignature("TIFF Image", ".tiff", bytes.fromhex("49492A00"), None, category="Images"),
    FileSignature("Bitmap Image", ".bmp", bytes.fromhex("424D"), None, category="Images"),
    FileSignature("WebP Image", ".webp", bytes.fromhex("52494646"), None, category="Images"),
    FileSignature("Adobe Photoshop Document", ".psd", bytes.fromhex("38425053"), None, category="Images"),
]

DOCUMENT_SIGNATURES = [
    FileSignature("PDF Document", ".pdf", b"%PDF-", b"%%EOF", category="Documents"),
    FileSignature("Rich Text Format", ".rtf", bytes.fromhex("7B5C727466"), None, category="Documents"),
    FileSignature("XML Document", ".xml", b"<?xml", None, category="Documents"),
    FileSignature("Microsoft Word Document (DOC)", ".doc", bytes.fromhex("D0CF11E0A1B11AE1"), None, category="Documents"),
    FileSignature("Microsoft Excel Spreadsheet (XLS)", ".xls", bytes.fromhex("D0CF11E0A1B11AE1"), None, category="Documents"),
    FileSignature("Microsoft PowerPoint Presentation (PPT)", ".ppt", bytes.fromhex("D0CF11E0A1B11AE1"), None, category="Documents"),
    FileSignature("Office Open XML Document (DOCX)", ".docx", bytes.fromhex("504B0304"), None, category="Documents"),
    FileSignature("Office Open XML Spreadsheet (XLSX)", ".xlsx", bytes.fromhex("504B0304"), None, category="Documents"),
    FileSignature("Office Open XML Presentation (PPTX)", ".pptx", bytes.fromhex("504B0304"), None, category="Documents"),
]

ARCHIVE_SIGNATURES = [
    FileSignature("ZIP Archive", ".zip", bytes.fromhex("504B0304"), bytes.fromhex("504B0506"), category="Archives"),
    FileSignature("RAR Archive", ".rar", bytes.fromhex("526172211A0700"), None, category="Archives"),
    FileSignature("7-Zip Archive", ".7z", bytes.fromhex("377ABCAF271C"), None, category="Archives"),
    FileSignature("GZIP Archive", ".gz", bytes.fromhex("1F8B08"), None, category="Archives"),
    FileSignature("BZIP2 Archive", ".bz2", bytes.fromhex("425A68"), None, category="Archives"),
    FileSignature("TAR Archive", ".tar", bytes.fromhex("7573746172"), None, category="Archives"),
    FileSignature("ISO Image", ".iso", bytes.fromhex("4344303031"), None, category="Archives"),
]

AUDIO_SIGNATURES = [
    FileSignature("MP3 Audio", ".mp3", bytes.fromhex("494433"), None, category="Audio"),
    FileSignature("MP2 Audio", ".mp2", bytes.fromhex("494433"), None, category="Audio"),
    FileSignature("Audio (WAV)", ".wav", bytes.fromhex("52494646"), None, category="Audio"),
    FileSignature("Audio (FLAC)", ".flac", bytes.fromhex("664C6143"), None, category="Audio"),
    FileSignature("Audio (OGG)", ".ogg", bytes.fromhex("4F676753"), None, category="Audio"),
]

VIDEO_SIGNATURES = [
    FileSignature("MP4 Video", ".mp4", bytes.fromhex("0000001866747970"), None, category="Video"),
    FileSignature("Matroska Video", ".mkv", bytes.fromhex("1A45DFA3"), None, category="Video"),
    FileSignature("Video (AVI)", ".avi", bytes.fromhex("52494646"), None, category="Video"),
    FileSignature("Video (QuickTime/MOV)", ".mov", bytes.fromhex("000000146674797071742020"), None, category="Video"),
    FileSignature("Video (MPEG)", ".mpg", bytes.fromhex("000001BA"), None, category="Video"),
    FileSignature("Video (WMV)", ".wmv", bytes.fromhex("3026B2758E66CF11"), None, category="Video"),
]

EXECUTABLE_SIGNATURES = [
    FileSignature("Windows Executable (PE)", ".exe", bytes.fromhex("4D5A"), None, category="Executables"),
    FileSignature("ELF Executable", ".elf", bytes.fromhex("7F454C46"), None, category="Executables"),
]

DATABASE_SIGNATURES = [
    FileSignature("SQLite Database", ".sqlite", b"SQLite format 3\x00", None, category="Databases"),
]

DEFAULT_SIGNATURE_GROUPS = [
    ("Images", IMAGES_SIGNATURES),
    ("Documents", DOCUMENT_SIGNATURES),
    ("Archives", ARCHIVE_SIGNATURES),
    ("Audio", AUDIO_SIGNATURES),
    ("Video", VIDEO_SIGNATURES),
    ("Executables", EXECUTABLE_SIGNATURES),
    ("Databases", DATABASE_SIGNATURES),
]

DEFAULT_SIGNATURES = [signature for _, group in DEFAULT_SIGNATURE_GROUPS for signature in group]

COLOR_PALETTE = {
    "background": "#10131a",
    "surface": "#1b2230",
    "surface_alt": "#232c3c",
    "primary": "#6c5ce7",
    "primary_light": "#a29bfe",
    "accent": "#00d1b2",
    "text": "#f5f6fa",
    "muted_text": "#a4b0be",
    "danger": "#ff7675",
}

USER_HOME = Path.home()
DEFAULT_RECOVERY_DIR = USER_HOME / "AuroraRecover"

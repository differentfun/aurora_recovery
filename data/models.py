"""Domain models used by the Aurora Recover utility."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional


class TargetType(str, Enum):
    """Type of entity a user can select as scan target."""

    DIRECTORY = "directory"
    IMAGE = "image"
    DEVICE = "device"
    TRASH = "trash"


class ScanMode(str, Enum):
    """High level scan strategy."""

    QUICK = "quick"
    TRASH = "trash"
    DEEP = "deep"


class ResultKind(str, Enum):
    """Classification for a scan result."""

    EXISTING = "existing"
    TRASH_ITEM = "trash_item"
    CARVED = "carved"


class ResultStatus(str, Enum):
    """Lifecycle status of a scan result."""

    ANALYZED = "analyzed"
    RECOVERABLE = "recoverable"
    RECOVERED = "recovered"
    FAILED = "failed"


@dataclass(slots=True)
class ScanTarget:
    """Represents an entity the user can scan."""

    identifier: str
    label: str
    path: Path
    target_type: TargetType
    description: str
    is_writable: bool = False
    metadata: Dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class FileSignature:
    """Signature description used during deep scans."""

    name: str
    extension: str
    header: bytes
    footer: Optional[bytes]
    category: str = "Other"

    def __post_init__(self) -> None:
        if not self.header:
            raise ValueError("FileSignature.header cannot be empty")
        if self.footer is not None and len(self.footer) == 0:
            self.footer = None
        if not self.category:
            self.category = "Other"


@dataclass(slots=True)
class ScanResult:
    """Represents a single entry from a scan."""

    identifier: str
    display_name: str
    location: Path
    size_bytes: int
    modified_at: Optional[datetime]
    status: ResultStatus
    kind: ResultKind
    origin: ScanMode
    metadata: Dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class FilesystemContext:
    """Context object used for filesystem-specific recovery."""

    name: str
    handler: object


@dataclass(slots=True)
class DeepScanSummary:
    """Container for deep scan results."""

    carved: List[CarvedMatch]
    filesystem_entries: List[ScanResult]
    context: Optional[FilesystemContext] = None


@dataclass(slots=True)
class CarvedMatch:
    """Metadata for a carved binary segment."""

    identifier: str
    source: Path
    signature: FileSignature
    offset_start: int
    offset_end: int
    size_bytes: int
    preview: bytes = field(repr=False)


@dataclass(slots=True)
class ProgressReport:
    """Generic progress update payload."""

    message: str
    ratio: float
    detail: str = ""


@dataclass(slots=True)
class RecoveryRequest:
    """Parameters describing a recovery operation."""

    item_id: str
    destination: Path
    overwrite: bool = False

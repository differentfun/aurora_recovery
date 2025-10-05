"""Application controller coordinating UI and backend services."""
from __future__ import annotations

import queue
import threading
from pathlib import Path
from typing import Callable, Iterable, Optional

from .config import APP_NAME, DEFAULT_SIGNATURES
from .models import (
    CarvedMatch,
    FileSignature,
    ProgressReport,
    ResultKind,
    ResultStatus,
    ScanMode,
    ScanResult,
    ScanTarget,
)
from .recovery import RecoveryManager
from .scanner import ScannerEngine
from .utils import ThreadedTask, is_display_available


class AppController:
    """High-level facade used by the launcher and UI."""

    def __init__(self) -> None:
        self.scanner = ScannerEngine(signatures=DEFAULT_SIGNATURES)
        self.recovery = RecoveryManager()
        self._event_queue: "queue.Queue[tuple[str, object]]" = queue.Queue()
        self._active_task: Optional[ThreadedTask] = None
        self._cancel_event: Optional[threading.Event] = None
        self._ui = None
        self._last_scan_results: list[ScanResult] = []
        self._last_carved_matches: list[CarvedMatch] = []
        self._targets_cache: list[ScanTarget] = []

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def run(self) -> int:
        if not is_display_available():
            print("No graphical display available. Use `python main.py --check` in headless environments.")
            return 1
        from .ui import RecoveryUI  # Imported lazily to avoid Tk initialization during tests

        self._ui = RecoveryUI(controller=self, app_name=APP_NAME)
        self.refresh_targets()
        self._schedule_event_pump()
        self._ui.mainloop()
        return 0

    def refresh_targets(self) -> None:
        self._targets_cache = self.scanner.list_all_targets()
        if self._ui:
            self._ui.populate_targets(self._targets_cache)

    # ------------------------------------------------------------------
    # Exposed operations for UI callbacks
    # ------------------------------------------------------------------
    def start_quick_scan(self, target_id: str) -> None:
        target = self._find_target(target_id)
        if not target:
            self._queue_event("error", ValueError("Target not found"))
            return
        self._launch_task(
            name="Quick scan",
            worker=lambda cancel_event: self._run_quick_scan(target, cancel_event),
        )

    def start_trash_scan(self, target_id: str) -> None:
        target = self._find_target(target_id)
        if not target:
            self._queue_event("error", ValueError("Recycle-bin path not found"))
            return
        self._launch_task(
            name="Trash scan",
            worker=lambda cancel_event: self._run_trash_scan(target, cancel_event),
        )

    def start_deep_scan(
        self,
        image_path: Path,
        *,
        signature_filter: Optional[Iterable[str]] = None,
        filesystem_filter: Optional[str] = None,
    ) -> None:
        if not image_path.exists():
            self._queue_event("error", FileNotFoundError(f"File not found: {image_path}"))
            return
        selected_signatures: Optional[list[FileSignature]] = None
        if signature_filter is not None:
            filter_set = set(signature_filter)
            selected_signatures = [sig for sig in self.scanner.signatures if sig.name in filter_set]
            if not selected_signatures:
                self._queue_event("error", ValueError("No matching signatures for deep scan"))
                return
        self._launch_task(
            name="Deep scan",
            worker=lambda cancel_event: self._run_deep_scan(
                image_path, cancel_event, selected_signatures, filesystem_filter
            ),
        )

    def recover_result(self, result_id: str, *, destination: Optional[Path] = None) -> None:
        result = next((entry for entry in self._last_scan_results if entry.identifier == result_id), None)
        if not result:
            self._queue_event("error", ValueError("Item is no longer available"))
            return
        self._launch_task(
            name="Recovery",
            worker=lambda cancel_event: self._perform_recovery(result, destination),
        )

    def recover_carved(self, match_id: str, *, destination: Optional[Path] = None) -> None:
        match = next((entry for entry in self._last_carved_matches if entry.identifier == match_id), None)
        if not match:
            self._queue_event("error", ValueError("Segment not found"))
            return
        self._launch_task(
            name="Carved recovery",
            worker=lambda cancel_event: self._perform_carved_recovery(match, destination),
        )

    def cancel_active_task(self) -> None:
        if self._cancel_event and not self._cancel_event.is_set():
            self._cancel_event.set()
            self._queue_event("status", "Cancelling operation...")

    # ------------------------------------------------------------------
    # Internal task runners
    # ------------------------------------------------------------------
    def _run_quick_scan(self, target: ScanTarget, cancel_event: threading.Event) -> None:
        self._queue_event("status", f"Quick scan of {target.label}")
        results = self.scanner.quick_scan(target.path, progress_cb=self._queue_progress, cancel_event=cancel_event)
        self._last_scan_results = results
        self._queue_event("scan_results", (ScanMode.QUICK, results))
        status_msg = "Operation cancelled" if cancel_event.is_set() else "Idle"
        self._queue_event("status", status_msg)

    def _run_trash_scan(self, target: ScanTarget, cancel_event: threading.Event) -> None:
        self._queue_event("status", f"Recycle bin scan for {target.label}")
        results = self.scanner.trash_scan(target.path, progress_cb=self._queue_progress, cancel_event=cancel_event)
        self._last_scan_results = results
        self._queue_event("scan_results", (ScanMode.TRASH, results))
        status_msg = "Operation cancelled" if cancel_event.is_set() else "Idle"
        self._queue_event("status", status_msg)

    def _run_deep_scan(
        self,
        image_path: Path,
        cancel_event: threading.Event,
        signatures: Optional[Iterable[FileSignature]] = None,
        filesystem: Optional[str] = None,
    ) -> None:
        self._queue_event("status", f"Deep scan of {image_path.name}")
        summary = self.scanner.deep_scan(
            image_path,
            progress_cb=self._queue_progress,
            cancel_event=cancel_event,
            signatures=signatures,
            filesystem=filesystem,
        )
        if summary.context:
            self.recovery.register_filesystem(summary.context.name, summary.context.handler)
        self._last_carved_matches = summary.carved
        self._queue_event("carved_results", summary.carved)
        self._last_scan_results = summary.filesystem_entries
        self._queue_event("scan_results", (ScanMode.DEEP, summary.filesystem_entries))
        status_msg = "Operation cancelled" if cancel_event.is_set() else "Idle"
        self._queue_event("status", status_msg)

    def _perform_recovery(self, result: ScanResult, destination: Optional[Path]) -> None:
        recovered_path = self.recovery.recover_scan_result(result, destination_dir=destination)
        result.status = ResultStatus.RECOVERED
        self._queue_event("recovery_complete", recovered_path)

    def _perform_carved_recovery(self, match: CarvedMatch, destination: Optional[Path]) -> None:
        recovered_path = self.recovery.recover_carved_match(match, destination_dir=destination)
        self._queue_event("recovery_complete", recovered_path)

    # ------------------------------------------------------------------
    # Task and event plumbing
    # ------------------------------------------------------------------
    def _launch_task(self, *, name: str, worker: Callable[[threading.Event], None]) -> None:
        if self._active_task and not self._active_task.done:
            self._queue_event("error", RuntimeError("Another operation is already running"))
            return

        cancel_event = threading.Event()
        self._cancel_event = cancel_event
        task = ThreadedTask(worker, cancel_event)
        self._active_task = task
        task.start()
        self._queue_event("task_started", name)

    def _queue_event(self, event_type: str, payload: object) -> None:
        self._event_queue.put((event_type, payload))

    def _queue_progress(self, report: ProgressReport) -> None:
        self._queue_event("progress", report)

    def _find_target(self, target_id: str) -> Optional[ScanTarget]:
        return next((target for target in self._targets_cache if target.identifier == target_id), None)

    def _schedule_event_pump(self) -> None:
        if not self._ui:
            return
        self._ui.after(100, self._drain_event_queue)

    def _drain_event_queue(self) -> None:
        if not self._ui:
            return
        try:
            while True:
                event, payload = self._event_queue.get_nowait()
                handler_name = f"handle_{event}"
                if hasattr(self._ui, handler_name):
                    getattr(self._ui, handler_name)(payload)
        except queue.Empty:
            pass
        finally:
            if self._active_task and self._active_task.done:
                task = self._active_task
                was_cancelled = bool(self._cancel_event and self._cancel_event.is_set())
                self._active_task = None
                self._cancel_event = None
                self._queue_event("task_finished", {"cancelled": was_cancelled})
                if task and task.error:
                    self._queue_event("error", task.error)
            self._schedule_event_pump()

    # Convenience accessors ------------------------------------------------
    @property
    def targets(self) -> Iterable[ScanTarget]:
        return self._targets_cache

    @property
    def last_results(self) -> Iterable[ScanResult]:
        return self._last_scan_results

    @property
    def last_carved(self) -> Iterable[CarvedMatch]:
        return self._last_carved_matches

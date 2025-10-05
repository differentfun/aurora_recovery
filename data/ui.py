"""Tkinter-based GUI for the Aurora Recover prototype."""
from __future__ import annotations

import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Dict, Iterable, List, Optional

from .config import COLOR_PALETTE, DEFAULT_SIGNATURES, DEFAULT_SIGNATURE_GROUPS
from .models import CarvedMatch, ScanResult, ScanTarget, TargetType
from .utils import format_bytes, format_timestamp


class RecoveryUI(tk.Tk):
    """Main application window."""

    def __init__(self, *, controller, app_name: str) -> None:
        super().__init__()
        self.controller = controller
        self.title(app_name)
        self.geometry("1200x780")
        self.minsize(1024, 640)
        self.configure(bg=COLOR_PALETTE["background"])

        self.progress_var = tk.DoubleVar(value=0.0)
        self.status_var = tk.StringVar(value="Idle")
        self._targets_by_item: Dict[str, ScanTarget] = {}
        self._results_by_id: Dict[str, ScanResult] = {}
        self._carved_by_id: Dict[str, CarvedMatch] = {}
        self._targets_by_item: Dict[str, ScanTarget] = {}
        self._results_by_id: Dict[str, ScanResult] = {}
        self._carved_by_id: Dict[str, CarvedMatch] = {}
        self.signature_states: Dict[str, bool] = {sig.name: False for sig in DEFAULT_SIGNATURES}
        self.filesystem_value = "auto"
        self._running = False
        self.selected_target_id: str | None = None
        self.selected_target_label = tk.StringVar(value="No target selected")

        self.quick_btn: ttk.Button | None = None
        self.trash_btn: ttk.Button | None = None
        self.deep_btn: ttk.Button | None = None
        self.refresh_btn: ttk.Button | None = None
        self.stop_btn: ttk.Button | None = None
        self.device_btn: ttk.Button | None = None
        self.filter_btn: ttk.Button | None = None
        self.filesystem_btn: ttk.Button | None = None
        self.filesystem_display = tk.StringVar(value="Auto")

        self._build_style()
        self._build_layout()

    # ------------------------------------------------------------------
    # Layout / styling helpers
    # ------------------------------------------------------------------
    def _build_style(self) -> None:
        palette = COLOR_PALETTE
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Main.TFrame", background=palette["background"])
        style.configure("Surface.TFrame", background=palette["surface"], relief="flat")
        style.configure("Card.TLabelframe", background=palette["surface"], borderwidth=0, padding=12)
        style.configure("Card.TLabelframe.Label", foreground=palette["muted_text"], background=palette["surface"], font=("TkDefaultFont", 10, "bold"))
        style.configure("Primary.TButton", foreground=palette["text"], background=palette["primary"], padding=8)
        style.map(
            "Primary.TButton",
            foreground=[("disabled", palette["muted_text"]), ("pressed", palette["text"]), ("active", palette["text"])],
            background=[("pressed", palette["primary_light"]), ("active", palette["primary_light"])],
        )
        style.configure("Header.TLabel", background=palette["background"], foreground=palette["text"], font=("TkDefaultFont", 20, "bold"))
        style.configure("Subtitle.TLabel", background=palette["background"], foreground=palette["muted_text"], font=("TkDefaultFont", 11))
        style.configure("Section.TLabel", background=palette["surface"], foreground=palette["muted_text"], font=("TkDefaultFont", 10, "bold"))
        style.configure("Status.TLabel", foreground=palette["muted_text"], background=palette["background"])
        style.configure("Status.TFrame", background=palette["background"])
        style.configure("Treeview", background=palette["surface"], fieldbackground=palette["surface"], foreground=palette["text"], bordercolor=palette["surface"], rowheight=28)
        style.map(
            "Treeview",
            background=[("selected", palette["primary"]), ("alternate", palette["surface_alt"])],
            foreground=[("selected", palette["text"])],
        )
        style.configure("Treeview.Heading", background=palette["surface_alt"], foreground=palette["text"], relief="flat")
        style.configure("TNotebook", background=palette["surface"], tabmargins=4)
        style.configure("TNotebook.Tab", padding=(12, 6), background=palette["surface_alt"], foreground=palette["muted_text"])
        style.map(
            "TNotebook.Tab",
            background=[("selected", palette["primary"]), ("active", palette["primary_light"])],
            foreground=[("selected", palette["text"]), ("active", palette["text"])],
        )
        style.configure(
            "Filter.TCheckbutton",
            background=palette["surface"],
            foreground=palette["text"],
        )
        style.map(
            "Filter.TCheckbutton",
            background=[("active", palette["surface_alt"]), ("selected", palette["surface"])],
            foreground=[("active", palette["text"]), ("selected", palette["text"])],
        )

    def _build_layout(self) -> None:
        main_frame = ttk.Frame(self, style="Main.TFrame", padding=24)
        main_frame.pack(fill=tk.BOTH, expand=True)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(1, weight=1)

        # Header -------------------------------------------------------------------
        header = ttk.Frame(main_frame, style="Main.TFrame")
        header.grid(row=0, column=0, columnspan=2, sticky="ew")
        ttk.Label(header, text="Aurora Recover", style="Header.TLabel").pack(side=tk.LEFT)
        ttk.Label(header, text="Scan. Analyze. Recover.", style="Subtitle.TLabel").pack(side=tk.LEFT, padx=(12, 0))
        self.refresh_btn = ttk.Button(header, text="Refresh devices", command=self._on_refresh_targets)
        self.refresh_btn.pack(side=tk.RIGHT)

        # Controls -----------------------------------------------------------------
        controls = ttk.LabelFrame(main_frame, text="Source", style="Card.TLabelframe")
        controls.grid(row=1, column=0, sticky="nsw", padx=(0, 24), pady=(16, 0))
        controls.columnconfigure(0, weight=1)

        ttk.Label(controls, text="Selected target", style="Section.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(controls, textvariable=self.selected_target_label, style="Status.TLabel").grid(row=1, column=0, sticky="w", pady=(2, 8))
        self.device_btn = ttk.Button(controls, text="Select device...", command=self._on_select_device)
        self.device_btn.grid(row=2, column=0, sticky="ew", pady=(0, 16))

        self.quick_btn = ttk.Button(controls, text="Quick scan", style="Primary.TButton", command=self._on_quick_scan, state=tk.DISABLED)
        self.quick_btn.grid(row=3, column=0, sticky="ew", pady=(0, 8))
        self.trash_btn = ttk.Button(controls, text="Scan recycle bin", command=self._on_trash_scan, state=tk.DISABLED)
        self.trash_btn.grid(row=4, column=0, sticky="ew", pady=(0, 8))
        self.deep_btn = ttk.Button(controls, text="Deep scan image...", command=self._on_deep_scan)
        self.deep_btn.grid(row=5, column=0, sticky="ew")

        ttk.Label(controls, text="Filesystem", style="Section.TLabel").grid(row=6, column=0, sticky="w", pady=(16, 4))
        fs_frame = ttk.Frame(controls, style="Surface.TFrame")
        fs_frame.grid(row=7, column=0, sticky="ew")
        fs_frame.columnconfigure(0, weight=1)
        ttk.Label(fs_frame, textvariable=self.filesystem_display, style="Status.TLabel").grid(row=0, column=0, sticky="w")
        self.filesystem_btn = ttk.Button(fs_frame, text="Select filesystem...", command=self._on_select_filesystem)
        self.filesystem_btn.grid(row=0, column=1, sticky="e")

        ttk.Label(controls, text="Signatures", style="Section.TLabel").grid(row=8, column=0, sticky="w", pady=(16, 4))
        self.filter_btn = ttk.Button(controls, text="Filter types...", command=self._on_filter_types)
        self.filter_btn.grid(row=9, column=0, sticky="ew")
        self._update_filter_summary()

        ttk.Separator(controls, orient=tk.HORIZONTAL).grid(row=10, column=0, sticky="ew", pady=18)
        ttk.Label(controls, text="Actions", style="Section.TLabel").grid(row=11, column=0, sticky="w")
        self.recover_btn = ttk.Button(controls, text="Recover selection", command=self._on_recover_selected, state=tk.DISABLED)
        self.recover_btn.grid(row=12, column=0, sticky="ew", pady=(6, 0))

        # Results area --------------------------------------------------------------
        right_frame = ttk.LabelFrame(main_frame, text="Results", style="Card.TLabelframe")
        right_frame.grid(row=1, column=1, sticky="nsew", pady=(16, 0))
        right_frame.columnconfigure(0, weight=1)
        right_frame.rowconfigure(1, weight=1)

        self.tab_control = ttk.Notebook(right_frame)
        self.tab_control.grid(row=0, column=0, sticky="nsew")
        self.tab_control.bind("<<NotebookTabChanged>>", self._on_tab_change)

        # Quick / trash tab ---------------------------------------------------------
        quick_container = ttk.Frame(self.tab_control, style="Surface.TFrame")
        quick_container.columnconfigure(0, weight=1)
        quick_container.rowconfigure(0, weight=1)
        self.tab_control.add(quick_container, text="File system")

        self.quick_tree = ttk.Treeview(
            quick_container,
            columns=("name", "size", "modified", "path"),
            show="headings",
            selectmode="browse",
        )
        self.quick_tree.heading("name", text="Name")
        self.quick_tree.heading("size", text="Size")
        self.quick_tree.heading("modified", text="Modified")
        self.quick_tree.heading("path", text="Path")
        self.quick_tree.column("name", width=200, anchor="w")
        self.quick_tree.column("size", width=120, anchor="center")
        self.quick_tree.column("modified", width=160, anchor="center")
        self.quick_tree.column("path", width=320, anchor="w")
        self.quick_tree.grid(row=0, column=0, sticky="nsew")
        self.quick_tree.bind("<<TreeviewSelect>>", self._on_selection_changed)

        quick_scroll = ttk.Scrollbar(quick_container, orient=tk.VERTICAL, command=self.quick_tree.yview)
        self.quick_tree.configure(yscroll=quick_scroll.set)
        quick_scroll.grid(row=0, column=1, sticky="ns")

        # Carved tab ---------------------------------------------------------------
        carved_container = ttk.Frame(self.tab_control, style="Surface.TFrame")
        carved_container.columnconfigure(0, weight=1)
        carved_container.rowconfigure(0, weight=1)
        self.tab_control.add(carved_container, text="File carving")

        self.carved_tree = ttk.Treeview(
            carved_container,
            columns=("signature", "offset", "size"),
            show="headings",
            selectmode="browse",
        )
        self.carved_tree.heading("signature", text="Signature")
        self.carved_tree.heading("offset", text="Offset")
        self.carved_tree.heading("size", text="Size")
        self.carved_tree.column("signature", width=260, anchor="w")
        self.carved_tree.column("offset", width=200, anchor="center")
        self.carved_tree.column("size", width=160, anchor="center")
        self.carved_tree.grid(row=0, column=0, sticky="nsew")
        self.carved_tree.bind("<<TreeviewSelect>>", self._on_selection_changed)

        carved_scroll = ttk.Scrollbar(carved_container, orient=tk.VERTICAL, command=self.carved_tree.yview)
        self.carved_tree.configure(yscroll=carved_scroll.set)
        carved_scroll.grid(row=0, column=1, sticky="ns")

        # Detail panel -------------------------------------------------------------
        detail_frame = ttk.Frame(right_frame, style="Surface.TFrame")
        detail_frame.grid(row=1, column=0, sticky="ew", pady=(16, 0))
        detail_frame.columnconfigure(0, weight=1)

        ttk.Label(detail_frame, text="Details", style="Section.TLabel").grid(row=0, column=0, sticky="w")
        self.detail_text = tk.Text(
            detail_frame,
            height=6,
            wrap="word",
            bg=COLOR_PALETTE["surface_alt"],
            fg=COLOR_PALETTE["text"],
            bd=0,
            highlightthickness=0,
            relief="flat",
        )
        self.detail_text.grid(row=1, column=0, sticky="ew", pady=(6, 0))
        self.detail_text.configure(state=tk.DISABLED)

        # Status bar ---------------------------------------------------------------
        status_frame = ttk.Frame(main_frame, style="Status.TFrame")
        status_frame.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(18, 0))
        status_frame.columnconfigure(1, weight=1)
        status_frame.columnconfigure(2, minsize=90)

        ttk.Label(status_frame, textvariable=self.status_var, style="Status.TLabel").grid(row=0, column=0, sticky="w")
        progress = ttk.Progressbar(status_frame, variable=self.progress_var, maximum=1.0)
        progress.grid(row=0, column=1, sticky="ew", padx=(16, 0))
        self.stop_btn = ttk.Button(status_frame, text="Stop", command=self._on_stop, state=tk.DISABLED)
        self.stop_btn.grid(row=0, column=2, sticky="e")

    # ------------------------------------------------------------------
    # Population helpers
    # ------------------------------------------------------------------
    def populate_targets(self, targets: Iterable[ScanTarget]) -> None:
        self._targets_by_item = {target.identifier: target for target in targets}
        if self.selected_target_id not in self._targets_by_item:
            self.selected_target_id = next(iter(self._targets_by_item), None)
        self._update_selected_label()
        self._update_target_buttons(self._get_selected_target())

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------
    def _on_refresh_targets(self) -> None:
        self.controller.refresh_targets()

    def _on_select_device(self) -> None:
        if not self._targets_by_item:
            messagebox.showinfo("No devices", "No devices available. Refresh targets first.")
            return
        dialog = DeviceSelectionDialog(self, list(self._targets_by_item.values()), self.selected_target_id)
        selection = dialog.show()
        if selection and selection in self._targets_by_item:
            self.selected_target_id = selection
        elif selection is None:
            # User cancelled; keep current selection
            pass
        elif not self._targets_by_item:
            self.selected_target_id = None
        self._update_target_buttons(self._get_selected_target())

    def _on_filter_types(self) -> None:
        dialog = SignatureFilterDialog(self, DEFAULT_SIGNATURES, self.signature_states)
        updated = dialog.show()
        if updated:
            self.signature_states = updated
            self._update_filter_summary()

    def _on_select_filesystem(self) -> None:
        dialog = FilesystemDialog(self, self.filesystem_value)
        selection = dialog.show()
        if selection:
            self.filesystem_value = selection
            label = "Auto" if selection == "auto" else selection.upper()
            self.filesystem_display.set(label)

    def _get_selected_target(self) -> ScanTarget | None:
        if not self.selected_target_id:
            return None
        return self._targets_by_item.get(self.selected_target_id)

    def _update_target_buttons(self, target: ScanTarget | None) -> None:
        self._update_selected_label()
        if self._running:
            quick_state = tk.DISABLED
            trash_state = tk.DISABLED
        else:
            quick_state = tk.NORMAL if target and target.target_type == TargetType.DIRECTORY else tk.DISABLED
            trash_state = tk.NORMAL if target and target.target_type == TargetType.TRASH else tk.DISABLED
        if self.quick_btn:
            self.quick_btn.configure(state=quick_state)
        if self.trash_btn:
            self.trash_btn.configure(state=trash_state)

    def _update_selected_label(self) -> None:
        target = self._get_selected_target()
        if target:
            self.selected_target_label.set(f"{target.label} — {target.path}")
        else:
            self.selected_target_label.set("No target selected")

    def _update_filter_summary(self) -> None:
        enabled = sum(1 for enabled in self.signature_states.values() if enabled)
        total = len(self.signature_states)
        if self.filter_btn:
            self.filter_btn.configure(text=f"Filter types... ({enabled}/{total})")

    def _set_running_state(self, running: bool) -> None:
        self._running = running
        button_state = tk.DISABLED if running else tk.NORMAL
        if self.refresh_btn:
            self.refresh_btn.configure(state=button_state)
        if self.deep_btn:
            self.deep_btn.configure(state=button_state)
        if self.device_btn:
            self.device_btn.configure(state=button_state)
        if self.filter_btn:
            self.filter_btn.configure(state=button_state)
        if self.filesystem_btn:
            self.filesystem_btn.configure(state=button_state)
        if running:
            if self.quick_btn:
                self.quick_btn.configure(state=tk.DISABLED)
            if self.trash_btn:
                self.trash_btn.configure(state=tk.DISABLED)
            if self.stop_btn:
                self.stop_btn.configure(state=tk.NORMAL)
        else:
            if self.stop_btn:
                self.stop_btn.configure(state=tk.DISABLED)
            self._update_target_buttons(self._get_selected_target())

    def _get_selected_signatures(self) -> list[str]:
        return [name for name, enabled in self.signature_states.items() if enabled]

    def _on_quick_scan(self) -> None:
        target = self._get_selected_target()
        if not target or target.target_type != TargetType.DIRECTORY:
            messagebox.showwarning("Select a folder", "Choose a directory to scan")
            return
        self._reset_progress()
        self.controller.start_quick_scan(target.identifier)

    def _on_trash_scan(self) -> None:
        target = self._get_selected_target()
        if not target or target.target_type != TargetType.TRASH:
            messagebox.showwarning("Select recycle bin", "Choose a recycle-bin target")
            return
        self._reset_progress()
        self.controller.start_trash_scan(target.identifier)
        self.tab_control.select(0)

    def _on_deep_scan(self) -> None:
        target = self._get_selected_target()
        if target and target.target_type == TargetType.DEVICE:
            file_path = str(target.path)
        else:
            file_path = filedialog.askopenfilename(title="Select disk image")
            if not file_path:
                return
        selected_signatures = self._get_selected_signatures()
        if not selected_signatures:
            messagebox.showwarning("Select signatures", "Choose at least one file type for the deep scan")
            return
        fs_value = (self.filesystem_value or "").strip().lower()
        filesystem = None if fs_value in {"", "auto"} else fs_value
        self._reset_progress()
        self.controller.start_deep_scan(
            Path(file_path),
            signature_filter=selected_signatures,
            filesystem_filter=filesystem,
        )
        self.tab_control.select(1)

    def _on_stop(self) -> None:
        self.controller.cancel_active_task()

    def _on_selection_changed(self, _event=None) -> None:
        if self.tab_control.index(self.tab_control.select()) == 0:
            selection = self.quick_tree.selection()
            if not selection:
                self._update_detail("No item selected")
                self.recover_btn.configure(state=tk.DISABLED)
                return
            item_id = selection[0]
            result = self._results_by_id.get(item_id)
            if not result:
                return
            detail = (
                f"Name: {result.display_name}\n"
                f"Size: {format_bytes(result.size_bytes)}\n"
                f"Modified: {format_timestamp(result.modified_at)}\n"
                f"Path: {result.location}"
            )
            self._update_detail(detail)
            self.recover_btn.configure(state=tk.NORMAL)
        else:
            selection = self.carved_tree.selection()
            if not selection:
                self._update_detail("No segment selected")
                self.recover_btn.configure(state=tk.DISABLED)
                return
            item_id = selection[0]
            match = self._carved_by_id.get(item_id)
            if not match:
                return
            detail = (
                f"Signature: {match.signature.name}\n"
                f"Offset: 0x{match.offset_start:x} - 0x{match.offset_end:x}\n"
                f"Size: {format_bytes(match.size_bytes)}\n"
                f"Source: {match.source}"
            )
            self._update_detail(detail)
            self.recover_btn.configure(state=tk.NORMAL)

    def _on_recover_selected(self) -> None:
        destination_dir = filedialog.askdirectory(title="Select output directory")
        dest_path = Path(destination_dir) if destination_dir else None
        if self.tab_control.index(self.tab_control.select()) == 0:
            selection = self.quick_tree.selection()
            if not selection:
                return
            item_id = selection[0]
            self.controller.recover_result(item_id, destination=dest_path)
        else:
            selection = self.carved_tree.selection()
            if not selection:
                return
            item_id = selection[0]
            self.controller.recover_carved(item_id, destination=dest_path)

    def _on_tab_change(self, _event=None) -> None:
        self._on_selection_changed()

    # ------------------------------------------------------------------
    # Controller callbacks (handled via controller queue)
    # ------------------------------------------------------------------
    def handle_task_started(self, task_name: str) -> None:
        self._set_running_state(True)

    def handle_task_finished(self, payload) -> None:
        self._set_running_state(False)
        if payload and isinstance(payload, dict) and payload.get("cancelled"):
            self.status_var.set("Operation cancelled")
            self.progress_var.set(0.0)

    def handle_status(self, message: str) -> None:
        self.status_var.set(message)

    def handle_progress(self, report) -> None:
        self.status_var.set(report.message)
        self.progress_var.set(report.ratio)

    def handle_scan_results(self, payload) -> None:
        _mode, results = payload
        self.quick_tree.delete(*self.quick_tree.get_children())
        self._results_by_id = {}
        for result in results:
            values = (
                result.display_name,
                format_bytes(result.size_bytes),
                format_timestamp(result.modified_at),
                str(result.location),
            )
            self.quick_tree.insert("", tk.END, iid=result.identifier, values=values)
            self._results_by_id[result.identifier] = result
        if results:
            self.quick_tree.selection_set(results[0].identifier)
            self._on_selection_changed()
        else:
            self._update_detail("No results found")
            self.recover_btn.configure(state=tk.DISABLED)
        self.tab_control.select(0)

    def handle_carved_results(self, matches: Iterable[CarvedMatch]) -> None:
        self.carved_tree.delete(*self.carved_tree.get_children())
        self._carved_by_id = {}
        matches = list(matches)
        for match in matches:
            values = (
                f"{match.signature.name} ({match.signature.extension})",
                f"0x{match.offset_start:x}",
                format_bytes(match.size_bytes),
            )
            self.carved_tree.insert("", tk.END, iid=match.identifier, values=values)
            self._carved_by_id[match.identifier] = match
        if matches:
            self.carved_tree.selection_set(matches[0].identifier)
            self._on_selection_changed()
        else:
            self._update_detail("No carved segments found")
            self.recover_btn.configure(state=tk.DISABLED)
        self.tab_control.select(1)

    def handle_error(self, exc: Exception) -> None:
        messagebox.showerror("Error", str(exc))
        self.status_var.set("Error")
        self.progress_var.set(0.0)

    def handle_recovery_complete(self, path: Path) -> None:
        messagebox.showinfo("Recovery completed", f"File saved to\n{path}")
        self.status_var.set("Recovery completed")
        self.progress_var.set(1.0)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _reset_progress(self) -> None:
        self.progress_var.set(0.0)
        self.status_var.set("Processing...")
        self.recover_btn.configure(state=tk.DISABLED)
        self._update_detail("Waiting for results...")

    def _update_detail(self, text: str) -> None:
        self.detail_text.configure(state=tk.NORMAL)
        self.detail_text.delete("1.0", tk.END)
        self.detail_text.insert(tk.END, text)
        self.detail_text.configure(state=tk.DISABLED)


class DeviceSelectionDialog(tk.Toplevel):
    def __init__(self, parent: tk.Tk, targets: list[ScanTarget], selected_id: Optional[str]) -> None:
        super().__init__(parent)
        self.title("Select device")
        self.geometry("640x420")
        self.transient(parent)
        self.grab_set()
        self.result_id: Optional[str] = None
        self._targets_map: Dict[str, ScanTarget] = {t.identifier: t for t in targets}
        self.protocol("WM_DELETE_WINDOW", self._on_cancel)

        frame = ttk.Frame(self, padding=12)
        frame.pack(fill=tk.BOTH, expand=True)
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)

        columns = ("model", "path", "type", "size")
        self.tree = ttk.Treeview(frame, columns=columns, show="tree headings", selectmode="browse")
        self.tree.heading("#0", text="Name")
        self.tree.heading("model", text="Model")
        self.tree.heading("path", text="Path")
        self.tree.heading("type", text="Type")
        self.tree.heading("size", text="Size")
        self.tree.column("#0", width=220, anchor="w")
        self.tree.column("model", width=160, anchor="w")
        self.tree.column("path", width=240, anchor="w")
        self.tree.column("type", width=110, anchor="center")
        self.tree.column("size", width=120, anchor="e")
        self.tree.grid(row=0, column=0, sticky="nsew")

        scroll = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scroll.set)
        scroll.grid(row=0, column=1, sticky="ns")

        button_row = ttk.Frame(frame)
        button_row.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(12, 0))
        button_row.columnconfigure(0, weight=1)
        ttk.Button(button_row, text="Cancel", command=self._on_cancel).grid(row=0, column=1, padx=(8, 0))
        ttk.Button(button_row, text="Select", command=self._on_select).grid(row=0, column=2, padx=(8, 0))

        self._populate_tree(targets)
        if selected_id and selected_id in self._targets_map:
            self.tree.selection_set(selected_id)
            self.tree.focus(selected_id)

        self.tree.bind("<Double-1>", lambda _event: self._on_select())
        self.bind("<Return>", lambda _event: self._on_select())
        self.bind("<Escape>", lambda _event: self._on_cancel())

    def _populate_tree(self, targets: list[ScanTarget]) -> None:
        devices_node = self.tree.insert("", tk.END, text="Devices", open=True)
        mounts_node = self.tree.insert("", tk.END, text="Mounts & folders", open=True)
        trash_node = self.tree.insert("", tk.END, text="Recycle bins", open=True)
        parent_nodes: Dict[str, str] = {}

        for target in targets:
            if target.target_type == TargetType.DEVICE:
                metadata = target.metadata or {}
                model = metadata.get("device_model", "-") or "-"
                size_bytes = metadata.get("size_bytes") or "0"
                try:
                    size_display = format_bytes(int(size_bytes)) if int(size_bytes) > 0 else "-"
                except (ValueError, TypeError):
                    size_display = "-"
                is_partition = metadata.get("is_partition") == "1"
                parent_id = metadata.get("parent_id")
                parent = parent_nodes.get(parent_id, devices_node) if is_partition else devices_node
                node = self.tree.insert(
                    parent,
                    tk.END,
                    iid=target.identifier,
                    text=target.label,
                    values=(model, str(target.path), "Partition" if is_partition else "Disk", size_display),
                )
                if not is_partition:
                    parent_nodes[target.identifier] = node
            elif target.target_type == TargetType.TRASH:
                self.tree.insert(
                    trash_node,
                    tk.END,
                    iid=target.identifier,
                    text=target.label,
                    values=("-", str(target.path), "Recycle bin", "-"),
                )
            else:
                self.tree.insert(
                    mounts_node,
                    tk.END,
                    iid=target.identifier,
                    text=target.label,
                    values=("-", str(target.path), "Directory", "-"),
                )

    def _on_select(self) -> None:
        selection = self.tree.selection()
        if not selection:
            return
        item = selection[0]
        if item not in self._targets_map:
            return
        self.result_id = item
        self.destroy()

    def _on_cancel(self) -> None:
        self.result_id = None
        self.destroy()

    def show(self) -> Optional[str]:
        self.wait_window()
        return self.result_id


class SignatureFilterDialog(tk.Toplevel):
    def __init__(self, parent: tk.Tk, signatures, current: Dict[str, bool]) -> None:
        super().__init__(parent)
        self.title("Filter signatures")
        self.transient(parent)
        self.grab_set()
        self.resizable(False, False)
        self.result: Optional[Dict[str, bool]] = None
        self.protocol("WM_DELETE_WINDOW", self._on_cancel)
        self.configure(bg=COLOR_PALETTE["background"])

        container = ttk.Frame(self, padding=12, style="Surface.TFrame")
        container.pack(fill=tk.BOTH, expand=True)

        notebook = ttk.Notebook(container, style="TNotebook")
        notebook.pack(fill=tk.BOTH, expand=True)

        self._entry_vars: Dict[str, tk.BooleanVar] = {}
        for category, group in DEFAULT_SIGNATURE_GROUPS:
            tab = ttk.Frame(notebook, style="Surface.TFrame")
            notebook.add(tab, text=category)
            for signature in group:
                var = tk.BooleanVar(value=current.get(signature.name, False))
                label = f"{signature.name} ({signature.extension})"
                chk = ttk.Checkbutton(tab, text=label, variable=var, style="Filter.TCheckbutton")
                chk.pack(anchor="w", pady=2)
                self._entry_vars[signature.name] = var

        button_row = ttk.Frame(container, style="Surface.TFrame")
        button_row.pack(fill=tk.X, pady=(12, 0))
        ttk.Button(button_row, text="Cancel", command=self._on_cancel).pack(side=tk.RIGHT, padx=(8, 0))
        ttk.Button(button_row, text="Apply", style="Primary.TButton", command=self._on_apply).pack(side=tk.RIGHT)

        self.bind("<Return>", lambda _event: self._on_apply())
        self.bind("<Escape>", lambda _event: self._on_cancel())

    def _on_apply(self) -> None:
        self.result = {name: var.get() for name, var in self._entry_vars.items()}
        self.destroy()

    def _on_cancel(self) -> None:
        self.result = None
        self.destroy()

    def show(self) -> Optional[Dict[str, bool]]:
        self.wait_window()
        return self.result

    def _show_selected_category(self) -> None:
        # legacy; no-op with notebook layout
        return


class FilesystemDialog(tk.Toplevel):
    OPTIONS = [
        ("Auto", "auto"),
        ("NTFS", "ntfs"),
        ("FAT", "fat"),
        ("FAT32", "fat32"),
        ("EXT", "ext"),
        ("EXT2", "ext2"),
        ("EXT3", "ext3"),
        ("EXT4", "ext4"),
        ("HFS", "hfs"),
        ("HFS+", "hfs+"),
        ("APFS", "apfs"),
    ]

    def __init__(self, parent: tk.Tk, current: str) -> None:
        super().__init__(parent)
        self.title("Select filesystem")
        self.transient(parent)
        self.grab_set()
        self.resizable(False, False)
        self.result: Optional[str] = None
        self.protocol("WM_DELETE_WINDOW", self._on_cancel)
        self.configure(bg=COLOR_PALETTE["background"])
        frame = ttk.Frame(self, padding=12)
        frame.pack(fill=tk.BOTH, expand=True)
        self.var = tk.StringVar(value=current or "auto")
        for idx, (label, value) in enumerate(self.OPTIONS):
            ttk.Radiobutton(frame, text=label, value=value, variable=self.var).grid(row=idx, column=0, sticky="w", pady=2)
        button_row = ttk.Frame(frame)
        button_row.grid(row=len(self.OPTIONS), column=0, sticky="ew", pady=(12, 0))
        ttk.Button(button_row, text="Cancel", command=self._on_cancel).pack(side=tk.RIGHT, padx=(8, 0))
        ttk.Button(button_row, text="Apply", command=self._on_apply).pack(side=tk.RIGHT)
        self.bind("<Return>", lambda _event: self._on_apply())
        self.bind("<Escape>", lambda _event: self._on_cancel())

    def _on_apply(self) -> None:
        self.result = self.var.get() or "auto"
        self.destroy()

    def _on_cancel(self) -> None:
        self.result = None
        self.destroy()

    def show(self) -> Optional[str]:
        self.wait_window()
        return self.result

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
import logging
import subprocess
import sys
import time

from PySide6.QtCore import QObject, QThread, QTimer, Qt, Signal, Slot
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMenu,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QSplitter,
    QStackedWidget,
    QStyle,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from persistence_radar import __version__
from persistence_radar.core.baseline import BaselineDiff, compare_findings
from persistence_radar.core.app_logging import get_log_dir, install_global_exception_hook, setup_logging
from persistence_radar.core.database import RadarDatabase
from persistence_radar.core.models import utc_now_iso
from persistence_radar.core.reporting import export_report
from persistence_radar.core.scan import ScanResult, coverage_catalog, run_scan
from persistence_radar.core.table_sorting import chain_severity, reputation_score, risk_score, severity_rank, sort_items, team_id
from persistence_radar.core.timeline import events_from_diff, export_timeline
from persistence_radar.core.trust import apply_trust
from persistence_radar.core.malware_kb import malware_kb
from persistence_radar.gui.components import EmptyStateWidget, FilterBar, FindingDetailPanel, KeyValueGrid, SeverityBadge, StatCard
from persistence_radar.gui.icons import app_icon


class ScanWorker(QObject):
    finished = Signal(object)
    progress = Signal(str)

    def __init__(self, root: str = "/") -> None:
        super().__init__()
        self.root = root

    @Slot()
    def run(self) -> None:
        self.progress.emit("Scanning persistence inventory")
        self.finished.emit(run_scan(root=self.root))


class ReputationTableItem(QTableWidgetItem):
    def __lt__(self, other) -> bool:
        return int(self.data(Qt.UserRole) or 0) < int(other.data(Qt.UserRole) or 0)


class RadarWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("macOS Persistence Radar")
        self.setWindowIcon(app_icon())
        self.resize(1380, 860)
        self.inventory_items = []
        self.findings = []
        self.filtered_inventory = []
        self.filtered_findings = []
        self.baseline_findings = []
        self.baseline_diff = BaselineDiff([], [], [])
        self.scanner_counts = {}
        self.scanner_warnings = []
        self.scanner_errors = []
        self.timeline_events = []
        self.posture = {}
        self.findings_sort: list[tuple[str, bool]] = [("severity", False), ("risk_score", False), ("new", False)]
        self.inventory_sort: list[tuple[str, bool]] = [("mechanism", True), ("title", True)]
        self.timeline_sort: list[tuple[str, bool]] = [("timestamp", False)]
        self.chain_sort: list[tuple[str, bool]] = [("risk_score", False)]
        self.last_scan_time = ""
        self.scan_started_at = 0.0
        self.scan_thread: QThread | None = None
        self.watch_timer = QTimer(self)
        self.watch_timer.timeout.connect(self.start_scan)
        self._build_ui()
        self.statusBar().showMessage("Ready. Read-only mode enabled.")
        self.apply_theme("Dark")
        self.update_all_views()

    def _build_ui(self) -> None:
        root = QWidget()
        outer = QHBoxLayout(root)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        self.sidebar = QListWidget()
        self.sidebar.setObjectName("Sidebar")
        self.sidebar.setFixedWidth(220)
        nav_items = (
            ("Dashboard", QStyle.SP_ComputerIcon),
            ("Welcome", QStyle.SP_DialogHelpButton),
            ("Inventory", QStyle.SP_DirIcon),
            ("Findings", QStyle.SP_FileDialogDetailedView),
            ("Coverage", QStyle.SP_DialogHelpButton),
            ("Chain View", QStyle.SP_ArrowRight),
            ("Timeline", QStyle.SP_FileDialogListView),
            ("Malware Library", QStyle.SP_MessageBoxInformation),
            ("Scanner Diagnostics", QStyle.SP_MessageBoxWarning),
            ("Baselines", QStyle.SP_DriveHDIcon),
            ("Watch Mode", QStyle.SP_BrowserReload),
            ("Reports", QStyle.SP_FileIcon),
            ("Settings", QStyle.SP_FileDialogContentsView),
            ("About", QStyle.SP_MessageBoxInformation),
        )
        for name, icon in nav_items:
            item = QListWidgetItem(name)
            item.setIcon(self.style().standardIcon(icon))
            item.setSizeHint(item.sizeHint().expandedTo(item.sizeHint()))
            self.sidebar.addItem(item)
        self.stack = QStackedWidget()
        self.sidebar.currentRowChanged.connect(self.stack.setCurrentIndex)
        outer.addWidget(self.sidebar)
        outer.addWidget(self.stack, 1)
        self.setCentralWidget(root)

        self._build_dashboard()
        self._build_welcome()
        self._build_inventory()
        self._build_findings()
        self._build_coverage()
        self._build_chains()
        self._build_timeline()
        self._build_malware_library()
        self._build_diagnostics()
        self._build_baselines()
        self._build_watch()
        self._build_reports()
        self._build_settings()
        self._build_about()
        self.sidebar.setCurrentRow(1)

    def page(self, title: str) -> tuple[QWidget, QVBoxLayout]:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(18)
        header = QLabel(title)
        header.setObjectName("PageTitle")
        layout.addWidget(header)
        self.stack.addWidget(widget)
        return widget, layout

    def _build_dashboard(self) -> None:
        _, layout = self.page("Dashboard")
        top = QHBoxLayout()
        self.scan_button = QPushButton("Run Scan")
        self.scan_button.setIcon(self.style().standardIcon(QStyle.SP_BrowserReload))
        self.scan_button.clicked.connect(self.start_scan)
        self.scan_status = QLabel("Ready")
        self.scan_status.setObjectName("MutedLabel")
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.hide()
        top.addWidget(self.scan_button)
        top.addWidget(self.scan_status)
        top.addStretch(1)
        top.addWidget(self.progress)
        layout.addLayout(top)
        self.dashboard_grid = QGridLayout()
        self.dashboard_grid.setSpacing(14)
        layout.addLayout(self.dashboard_grid)
        self.error_box = QTextEdit()
        self.error_box.setReadOnly(True)
        self.error_box.setObjectName("ErrorBox")
        self.error_box.hide()
        layout.addWidget(self.error_box)
        self.diagnostics_box = QTextEdit()
        self.diagnostics_box.setReadOnly(True)
        self.diagnostics_box.setObjectName("DetailText")
        layout.addWidget(self.diagnostics_box)
        self.heatmap_table = QTableWidget(0, 6)
        self.heatmap_table.setHorizontalHeaderLabels(["Mechanism", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
        self.heatmap_table.verticalHeader().hide()
        self.heatmap_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.heatmap_table)
        layout.addStretch(1)

    def _build_welcome(self) -> None:
        _, layout = self.page("Welcome")
        text = QLabel(
            "<b>Welcome to macOS Persistence Radar</b><br><br>"
            "This is a defensive macOS persistence audit tool. It is read-only by default, does not remove or modify system files, "
            "and does not install background persistence. Some paths may require Full Disk Access for best results."
        )
        text.setWordWrap(True)
        layout.addWidget(text)
        row = QHBoxLayout()
        start = QPushButton("Start First Scan")
        perms = QPushButton("View Required Permissions")
        start.clicked.connect(self.start_scan)
        perms.clicked.connect(self.show_permissions_help)
        row.addWidget(start)
        row.addWidget(perms)
        row.addStretch(1)
        layout.addLayout(row)
        layout.addStretch(1)

    def show_permissions_help(self) -> None:
        QMessageBox.information(
            self,
            "Full Disk Access",
            "Full Disk Access improves scan coverage for protected user and system locations.\n\n"
            "Steps:\nSystem Settings -> Privacy & Security -> Full Disk Access -> add macOS Persistence Radar.\n\n"
            "The app remains read-only. Permission improves visibility only.",
        )

    def _build_coverage(self) -> None:
        _, layout = self.page("Coverage")
        self.coverage_table = QTableWidget(0, 3)
        self.coverage_table.setHorizontalHeaderLabels(["Module", "Coverage", "MITRE / Risk Area"])
        self.coverage_table.verticalHeader().hide()
        self.coverage_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.coverage_table, 1)

    def _build_chains(self) -> None:
        _, layout = self.page("Chain View")
        self.chain_empty = EmptyStateWidget(
            "No chain relationships",
            "Run a scan to populate launchd, helper, native messaging, and executable relationships.",
        )
        layout.addWidget(self.chain_empty)
        self.chain_table = QTableWidget(0, 5)
        self.chain_table.setHorizontalHeaderLabels(["Risk Score", "Node Count", "Severity", "Chain", "Relationship"])
        self.chain_table.verticalHeader().hide()
        self.chain_table.horizontalHeader().setStretchLastSection(True)
        self.chain_table.horizontalHeader().sectionClicked.connect(lambda section: self.handle_sort("chain", section))
        layout.addWidget(self.chain_table, 1)

    def _build_timeline(self) -> None:
        _, layout = self.page("Timeline")
        controls = QHBoxLayout()
        self.timeline_from = QLineEdit()
        self.timeline_from.setPlaceholderText("From YYYY-MM-DD")
        self.timeline_to = QLineEdit()
        self.timeline_to.setPlaceholderText("To YYYY-MM-DD")
        self.timeline_severity = QComboBox()
        self.timeline_severity.addItems(["All", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
        self.timeline_mechanism = QComboBox()
        self.timeline_mechanism.addItem("All")
        export_button = QPushButton("Export Timeline")
        export_button.clicked.connect(self.export_timeline)
        for widget in (self.timeline_from, self.timeline_to, self.timeline_severity, self.timeline_mechanism, export_button):
            controls.addWidget(widget)
        layout.addLayout(controls)
        self.timeline_empty = EmptyStateWidget(
            "No timeline events",
            "Run a scan or compare against a baseline to generate observed, new, removed, modified, hash, and signature events.",
        )
        layout.addWidget(self.timeline_empty)
        self.timeline_table = QTableWidget(0, 6)
        self.timeline_table.setHorizontalHeaderLabels(["Time", "Event", "Severity", "Mechanism", "Item", "Path"])
        self.timeline_table.verticalHeader().hide()
        self.timeline_table.horizontalHeader().setStretchLastSection(True)
        self.timeline_table.horizontalHeader().sectionClicked.connect(lambda section: self.handle_sort("timeline", section))
        layout.addWidget(self.timeline_table, 1)
        self.timeline_from.textChanged.connect(self.update_timeline)
        self.timeline_to.textChanged.connect(self.update_timeline)
        self.timeline_severity.currentTextChanged.connect(self.update_timeline)
        self.timeline_mechanism.currentTextChanged.connect(self.update_timeline)

    def _build_malware_library(self) -> None:
        _, layout = self.page("Malware Library")
        self.malware_table = QTableWidget(0, 6)
        self.malware_table.setHorizontalHeaderLabels(["Family", "Type", "Artifact", "Pattern", "Confidence", "MITRE"])
        self.malware_table.verticalHeader().hide()
        self.malware_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.malware_table, 1)

    def _build_diagnostics(self) -> None:
        _, layout = self.page("Scanner Diagnostics")
        self.scanner_diagnostics = QTextEdit()
        self.scanner_diagnostics.setReadOnly(True)
        self.scanner_diagnostics.setPlainText("Run a scan to view per-module counts, warnings, errors, and skipped paths.")
        layout.addWidget(self.scanner_diagnostics, 1)

    def _build_inventory(self) -> None:
        _, layout = self.page("Inventory")
        self.inventory_filter_bar = FilterBar()
        self.inventory_filter_bar.connect_changed(self.apply_inventory_filters)
        layout.addWidget(self.inventory_filter_bar)
        splitter = QSplitter(Qt.Horizontal)
        self.inventory_table = QTableWidget(0, 8)
        self.inventory_columns = [
            ("severity", "Severity"),
            ("mechanism", "Mechanism"),
            ("title", "Item Name"),
            ("category", "Category"),
            ("owner", "Owner"),
            ("team_id", "Team ID"),
            ("created_time", "Created Time"),
            ("modified_time", "Modified Time"),
            ("first_seen", "First Seen"),
            ("last_seen", "Last Seen"),
            ("reputation", "Reputation Score"),
            ("path", "File Path"),
        ]
        self.inventory_table.setColumnCount(len(self.inventory_columns))
        self.inventory_table.setHorizontalHeaderLabels([label for _key, label in self.inventory_columns])
        self.inventory_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.inventory_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.inventory_table.verticalHeader().hide()
        self.inventory_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.inventory_table.horizontalHeader().setStretchLastSection(True)
        self.inventory_table.horizontalHeader().sectionClicked.connect(lambda section: self.handle_sort("inventory", section))
        self.inventory_table.itemSelectionChanged.connect(self.show_selected_inventory_detail)
        self.inventory_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.inventory_table.customContextMenuRequested.connect(lambda pos: self.show_table_context_menu(self.inventory_table, self.filtered_inventory, pos))
        self.inventory_detail_panel = FindingDetailPanel()
        splitter.addWidget(self.inventory_table)
        splitter.addWidget(self.inventory_detail_panel)
        splitter.setSizes([820, 480])
        layout.addWidget(splitter, 1)
        self.inventory_empty = EmptyStateWidget(
            "No inventory items discovered",
            "Run a scan. If this remains empty, review Dashboard diagnostics for unreadable paths, scanner errors, or active filters.",
        )
        layout.addWidget(self.inventory_empty)

    def _build_findings(self) -> None:
        _, layout = self.page("Findings")
        self.filter_bar = FilterBar()
        self.filter_bar.show_info.setChecked(False)
        self.filter_bar.connect_changed(self.apply_filters)
        layout.addWidget(self.filter_bar)
        quick = QHBoxLayout()
        for label, state in (
            ("Critical First", [("severity", False), ("risk_score", False)]),
            ("High Risk First", [("risk_score", False), ("severity", False)]),
            ("Newest First", [("first_seen", False)]),
            ("Oldest First", [("first_seen", True)]),
            ("Reputation Lowest", [("reputation", True)]),
            ("Reputation Highest", [("reputation", False)]),
        ):
            button = QPushButton(label)
            button.clicked.connect(lambda _checked=False, selected=state: self.set_findings_sort(selected))
            quick.addWidget(button)
        quick.addStretch(1)
        layout.addLayout(quick)
        splitter = QSplitter(Qt.Horizontal)
        self.findings_columns = [
            ("severity", "Severity"),
            ("title", "Title"),
            ("category", "Category"),
            ("mitre", "MITRE Technique"),
            ("risk_score", "Risk Score"),
            ("reputation", "Reputation Score"),
            ("first_seen", "First Seen"),
            ("last_seen", "Last Seen"),
            ("path", "File Path"),
            ("team_id", "Team ID"),
            ("signing", "Signing Status"),
            ("new", "New"),
        ]
        self.table = QTableWidget(0, len(self.findings_columns))
        self.table.setHorizontalHeaderLabels([label for _key, label in self.findings_columns])
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.verticalHeader().hide()
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().sectionClicked.connect(lambda section: self.handle_sort("findings", section))
        self.table.itemSelectionChanged.connect(self.show_selected_detail)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(lambda pos: self.show_table_context_menu(self.table, self.filtered_findings, pos))
        self.detail_panel = FindingDetailPanel()
        splitter.addWidget(self.table)
        splitter.addWidget(self.detail_panel)
        splitter.setSizes([820, 480])
        layout.addWidget(splitter, 1)
        self.findings_empty = EmptyStateWidget("No findings loaded", "Run a scan to populate the findings table.")
        layout.addWidget(self.findings_empty)

    def _build_baselines(self) -> None:
        _, layout = self.page("Baselines")
        row = QHBoxLayout()
        create = QPushButton("Create Baseline")
        compare = QPushButton("Compare Against Baseline")
        create.setIcon(self.style().standardIcon(QStyle.SP_DialogSaveButton))
        compare.setIcon(self.style().standardIcon(QStyle.SP_FileDialogDetailedView))
        create.clicked.connect(self.create_baseline)
        compare.clicked.connect(self.compare_baseline)
        row.addWidget(create)
        row.addWidget(compare)
        row.addStretch(1)
        layout.addLayout(row)
        self.baseline_summary = QLabel("No baseline comparison loaded.")
        self.baseline_summary.setObjectName("MutedLabel")
        layout.addWidget(self.baseline_summary)
        self.baseline_changes = QTextEdit()
        self.baseline_changes.setReadOnly(True)
        layout.addWidget(self.baseline_changes, 1)

    def _build_watch(self) -> None:
        _, layout = self.page("Watch Mode")
        row = QHBoxLayout()
        self.watch_status = QLabel("Stopped")
        self.watch_status.setObjectName("StatusStopped")
        start = QPushButton("Start")
        stop = QPushButton("Stop")
        start.setIcon(self.style().standardIcon(QStyle.SP_MediaPlay))
        stop.setIcon(self.style().standardIcon(QStyle.SP_MediaStop))
        start.clicked.connect(self.start_watch)
        stop.clicked.connect(self.stop_watch)
        row.addWidget(QLabel("Current status:"))
        row.addWidget(self.watch_status)
        row.addStretch(1)
        row.addWidget(start)
        row.addWidget(stop)
        layout.addLayout(row)
        self.watch_last_checked = QLabel("Last checked: never")
        self.watch_last_checked.setObjectName("MutedLabel")
        layout.addWidget(self.watch_last_checked)
        self.watch_changes = QTextEdit()
        self.watch_changes.setReadOnly(True)
        self.watch_changes.setPlainText("Recently detected changes will appear here. Persistent watch mode is not installed automatically.")
        layout.addWidget(self.watch_changes, 1)

    def _build_reports(self) -> None:
        _, layout = self.page("Reports")
        layout.addWidget(QLabel("Export client-ready reports from the latest scan."))
        if not self.inventory_items:
            empty = QLabel("No scan results are loaded yet. Run a scan before exporting a report.")
            empty.setObjectName("MutedLabel")
            layout.addWidget(empty)
        row = QHBoxLayout()
        for fmt in ("html", "json", "md"):
            button = QPushButton(f"Export {fmt.upper()}")
            button.setIcon(self.style().standardIcon(QStyle.SP_DialogSaveButton))
            button.clicked.connect(lambda _checked=False, selected=fmt: self.export(selected))
            row.addWidget(button)
        row.addStretch(1)
        layout.addLayout(row)
        layout.addStretch(1)

    def _build_settings(self) -> None:
        _, layout = self.page("Settings")
        self.theme_setting = QComboBox()
        self.theme_setting.addItems(["Dark", "Light", "System"])
        self.theme_setting.currentTextChanged.connect(self.apply_theme)
        self.threshold_setting = QComboBox()
        self.threshold_setting.addItems(["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
        self.threshold_setting.currentTextChanged.connect(self.update_all_views)
        self.export_folder = QPushButton(str(Path.cwd()))
        self.export_folder.clicked.connect(self.choose_export_folder)
        self.watch_interval = QSpinBox()
        self.watch_interval.setRange(5, 3600)
        self.watch_interval.setValue(30)
        self.include_apple = QCheckBox("Include system Apple items")
        self.include_apple.setChecked(True)
        self.include_browser = QCheckBox("Include browser extensions")
        self.include_browser.setChecked(True)
        self.include_shell = QCheckBox("Include shell startup files")
        self.include_shell.setChecked(True)
        self.include_profiles = QCheckBox("Include configuration profiles")
        self.include_profiles.setChecked(True)
        logs = QPushButton("Open Logs Folder")
        logs.clicked.connect(self.open_logs_folder)
        layout.addWidget(
            KeyValueGrid(
                [
                    ("Theme", self.theme_setting),
                    ("Severity threshold", self.threshold_setting),
                    ("Export folder", self.export_folder),
                    ("Watch interval seconds", self.watch_interval),
                    ("System Apple items", self.include_apple),
                    ("Browser extensions", self.include_browser),
                    ("Shell startup files", self.include_shell),
                    ("Configuration profiles", self.include_profiles),
                    ("Logs", logs),
                ]
            )
        )
        note = QLabel("Scanner settings are UI preferences for review workflows; scans remain read-only and do not modify system files.")
        note.setObjectName("MutedLabel")
        note.setWordWrap(True)
        layout.addWidget(note)
        layout.addStretch(1)

    def _build_about(self) -> None:
        _, layout = self.page("About")
        text = QLabel(
            f"<b>macOS Persistence Radar</b><br>"
            f"Version {__version__}<br><br>"
            "Defensive security tool for local-first macOS persistence inventory, DFIR triage, and audit workflows.<br><br>"
            "Author: Joe M<br>"
            "Company: Liquidsky Network Security<br>"
            "GitHub: https://fuzzlove.github.io<br>"
            "Website: https://liquidskysecurity.com<br><br>"
            "Use only on systems you own or are authorized to assess. The tool is read-only by default and does not remove or create persistence."
        )
        text.setWordWrap(True)
        layout.addWidget(text)
        layout.addStretch(1)

    def start_scan(self) -> None:
        if self.scan_thread and self.scan_thread.isRunning():
            return
        self.scan_button.setEnabled(False)
        self.scan_started_at = time.time()
        self.progress.show()
        self.scan_status.setText("Starting scan")
        self.statusBar().showMessage("Scanning persistence inventory...")
        self.scan_thread = QThread(self)
        self.worker = ScanWorker("/")
        self.worker.moveToThread(self.scan_thread)
        self.scan_thread.started.connect(self.worker.run)
        self.worker.progress.connect(self.scan_status.setText)
        self.worker.finished.connect(self.scan_finished)
        self.worker.finished.connect(self.scan_thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.scan_thread.finished.connect(self.scan_thread.deleteLater)
        self.scan_thread.start()

    @Slot(object)
    def scan_finished(self, result: ScanResult) -> None:
        old_inventory = self.inventory_items
        self.inventory_items = result.inventory_items
        self.findings = result.findings
        self.scanner_counts = result.scanner_counts
        self.scanner_warnings = result.warnings
        self.scanner_errors = result.errors
        self.coverage = result.coverage
        self.chains = result.chains
        self.timeline_events = result.timeline_events
        self.posture = result.posture
        self.last_scan_time = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
        duration = round(time.time() - self.scan_started_at, 2) if self.scan_started_at else result.scan_metadata.get("duration_seconds", 0)
        if self.watch_timer.isActive() and old_inventory:
            diff = compare_findings(old_inventory, self.inventory_items)
            self.watch_changes.setPlainText(self._diff_text(diff))
        self.scan_button.setEnabled(True)
        self.progress.hide()
        self.scan_status.setText(f"Last scan: {self.last_scan_time}")
        self.statusBar().showMessage(f"Scan completed in {duration}s: {len(self.inventory_items)} inventory items, {len(self.findings)} findings.")
        self.watch_last_checked.setText(f"Last checked: {self.last_scan_time}")
        self.update_all_views()
        self.show_scan_summary(duration)
        if result.warnings or result.errors:
            self.show_errors(result.warnings, result.errors)

    def show_scan_summary(self, duration: float) -> None:
        critical_high = sum(1 for item in self.inventory_items if str(item.severity) in {"CRITICAL", "HIGH"})
        QMessageBox.information(
            self,
            "Scan Complete",
            f"Total inventory items: {len(self.inventory_items)}\n"
            f"Total findings: {len(self.findings)}\n"
            f"Critical/high findings: {critical_high}\n"
            f"Scanner warnings: {len(self.scanner_warnings)}\n"
            f"Scanner errors: {len(self.scanner_errors)}\n"
            f"Scan duration: {duration}s\n\n"
            "Use Reports to export HTML, JSON, or Markdown.",
        )

    def show_errors(self, warnings: list[str], errors: list[str]) -> None:
        lines = []
        if warnings:
            lines.append("Scanner warnings:")
            lines.extend(f"- {warning}" for warning in warnings)
        if errors:
            lines.append("Scanner errors:")
            lines.extend(f"- {error}" for error in errors)
        self.error_box.setPlainText("\n".join(lines))
        self.error_box.show()
        logging.warning("Scanner warnings/errors: %s", "\n".join(lines))

    def update_all_views(self) -> None:
        self.update_dashboard()
        self.inventory_filter_bar.set_values(
            sorted({item.category for item in self.inventory_items}),
            sorted({item.mitre_technique_id for item in self.inventory_items if item.mitre_technique_id}),
        )
        self.filter_bar.set_values(
            sorted({item.category for item in self.findings}),
            sorted({item.mitre_technique_id for item in self.findings if item.mitre_technique_id}),
        )
        self.apply_inventory_filters()
        self.apply_filters()
        self.update_coverage()
        self.update_chains()
        self.update_timeline()
        self.update_malware_library()
        self.update_scanner_diagnostics()

    def update_coverage(self) -> None:
        coverage = getattr(self, "coverage", None) or coverage_catalog()
        self.coverage_table.setRowCount(len(coverage))
        for row, (key, value) in enumerate(sorted(coverage.items())):
            for col, text in enumerate((key, value["name"], value["mitre"])):
                item = QTableWidgetItem(text)
                item.setToolTip(text)
                self.coverage_table.setItem(row, col, item)
        self.coverage_table.resizeColumnsToContents()

    def update_chains(self) -> None:
        chains = getattr(self, "chains", [])
        chains = sort_items(chains, self.chain_sort, self.chain_key_map())
        self.chain_empty.setVisible(not chains)
        self.chain_table.setVisible(bool(chains))
        self.chain_table.setRowCount(len(chains))
        for row, chain in enumerate(chains):
            values = (
                str(chain.risk_score),
                str(len(chain.item_ids)),
                chain_severity(chain),
                chain.title,
                chain.relationship,
            )
            for col, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                self.chain_table.setItem(row, col, item)
        self.chain_table.resizeColumnsToContents()
        self.update_header_labels("chain")

    def update_timeline(self) -> None:
        events = getattr(self, "timeline_events", [])
        mechanisms = sorted({event.mechanism for event in events})
        current = self.timeline_mechanism.currentText() if hasattr(self, "timeline_mechanism") else "All"
        self.timeline_mechanism.blockSignals(True)
        self.timeline_mechanism.clear()
        self.timeline_mechanism.addItems(["All"] + mechanisms)
        self.timeline_mechanism.setCurrentText(current if current in mechanisms else "All")
        self.timeline_mechanism.blockSignals(False)
        severity = self.timeline_severity.currentText()
        mechanism = self.timeline_mechanism.currentText()
        start = self.timeline_from.text().strip()
        end = self.timeline_to.text().strip()
        filtered = []
        for event in events:
            if severity != "All" and event.severity != severity:
                continue
            if mechanism != "All" and event.mechanism != mechanism:
                continue
            if start and event.timestamp[:10] < start:
                continue
            if end and event.timestamp[:10] > end:
                continue
            filtered.append(event)
        filtered = sort_items(filtered, self.timeline_sort, self.timeline_key_map())
        self.timeline_empty.setVisible(not filtered)
        self.timeline_table.setVisible(bool(filtered))
        self.timeline_table.setRowCount(len(filtered))
        for row, event in enumerate(filtered):
            for col, value in enumerate((event.timestamp, event.event_type, event.severity, event.mechanism, event.title, event.path)):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                self.timeline_table.setItem(row, col, item)
        self.timeline_table.resizeColumnsToContents()
        self.update_header_labels("timeline")

    def update_malware_library(self) -> None:
        rows = malware_kb()
        self.malware_table.setRowCount(len(rows))
        for row, artifact in enumerate(rows):
            pattern = artifact["path_pattern"] or artifact["launchd_label"] or artifact["bundle_id"]
            values = (artifact["family"], artifact["artifact_type"], artifact["artifact_name"], pattern, artifact["confidence"], artifact["mitre_technique_id"])
            for col, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                item.setToolTip(str(artifact))
                self.malware_table.setItem(row, col, item)
        self.malware_table.resizeColumnsToContents()

    def finding_key_map(self) -> dict:
        new_ids = {item.id for item in self.baseline_diff.added}
        return {
            "severity": lambda item: severity_rank(str(item.severity)),
            "title": lambda item: item.title.lower(),
            "category": lambda item: item.category.lower(),
            "mitre": lambda item: item.mitre_technique_id.lower(),
            "risk_score": risk_score,
            "reputation": reputation_score,
            "first_seen": lambda item: item.first_seen or "",
            "last_seen": lambda item: item.last_seen or "",
            "path": lambda item: item.path.lower(),
            "team_id": lambda item: team_id(item).lower(),
            "signing": lambda item: item.code_signature_status.lower(),
            "new": lambda item: item.id in new_ids,
        }

    def inventory_key_map(self) -> dict:
        return {
            "severity": lambda item: severity_rank(str(item.severity)),
            "mechanism": lambda item: item.category.lower(),
            "title": lambda item: item.title.lower(),
            "category": lambda item: item.category.lower(),
            "owner": lambda item: item.owner.lower(),
            "team_id": lambda item: team_id(item).lower(),
            "created_time": lambda item: item.created_time or "",
            "modified_time": lambda item: item.modified_time or "",
            "first_seen": lambda item: item.first_seen or "",
            "last_seen": lambda item: item.last_seen or "",
            "reputation": reputation_score,
            "path": lambda item: item.path.lower(),
        }

    def timeline_key_map(self) -> dict:
        return {
            "timestamp": lambda event: event.timestamp,
            "event_type": lambda event: event.event_type.lower(),
            "severity": lambda event: severity_rank(event.severity),
            "mechanism": lambda event: event.mechanism.lower(),
            "title": lambda event: event.title.lower(),
            "path": lambda event: event.path.lower(),
        }

    def chain_key_map(self) -> dict:
        return {
            "risk_score": lambda chain: chain.risk_score,
            "node_count": lambda chain: len(chain.item_ids),
            "severity": lambda chain: severity_rank(chain_severity(chain)),
            "title": lambda chain: chain.title.lower(),
            "relationship": lambda chain: chain.relationship.lower(),
        }

    def table_sort_config(self, table_name: str) -> tuple[list[tuple[str, str]], list[tuple[str, bool]], list[tuple[str, bool]]]:
        if table_name == "findings":
            return self.findings_columns, self.findings_sort, [("severity", False), ("risk_score", False), ("new", False)]
        if table_name == "inventory":
            return self.inventory_columns, self.inventory_sort, [("mechanism", True), ("title", True)]
        if table_name == "timeline":
            return [("timestamp", "Time"), ("event_type", "Event"), ("severity", "Severity"), ("mechanism", "Mechanism"), ("title", "Item"), ("path", "Path")], self.timeline_sort, [("timestamp", False)]
        return [("risk_score", "Risk Score"), ("node_count", "Node Count"), ("severity", "Severity"), ("title", "Chain"), ("relationship", "Relationship")], self.chain_sort, [("risk_score", False)]

    def set_sort_state(self, table_name: str, state: list[tuple[str, bool]]) -> None:
        if table_name == "findings":
            self.findings_sort = state
            self.apply_filters()
        elif table_name == "inventory":
            self.inventory_sort = state
            self.apply_inventory_filters()
        elif table_name == "timeline":
            self.timeline_sort = state
            self.update_timeline()
        elif table_name == "chain":
            self.chain_sort = state
            self.update_chains()

    def set_findings_sort(self, state: list[tuple[str, bool]]) -> None:
        self.findings_sort = list(state)
        self.apply_filters()

    def handle_sort(self, table_name: str, section: int) -> None:
        columns, current_state, default_state = self.table_sort_config(table_name)
        key = columns[section][0]
        shift = bool(QApplication.keyboardModifiers() & Qt.ShiftModifier)
        if not shift:
            if current_state == default_state and current_state and current_state[0][0] == key:
                state = [(key, True)]
            elif current_state and current_state[0][0] == key and current_state[0][1] is True:
                state = [(key, False)]
            elif current_state and current_state[0][0] == key and current_state[0][1] is False:
                state = list(default_state)
            else:
                state = [(key, True)]
        else:
            state = list(current_state)
            existing = next((index for index, (sort_key, _ascending) in enumerate(state) if sort_key == key), None)
            if existing is None:
                state.append((key, True))
            else:
                _sort_key, ascending = state[existing]
                if ascending:
                    state[existing] = (key, False)
                else:
                    state.pop(existing)
            if not state:
                state = list(default_state)
        self.set_sort_state(table_name, state)

    def update_header_labels(self, table_name: str) -> None:
        columns, state, _default = self.table_sort_config(table_name)
        indicators = {key: "▲" if ascending else "▼" for key, ascending in state}
        labels = [f"{label} {indicators[key]}" if key in indicators else label for key, label in columns]
        table = {
            "findings": self.table,
            "inventory": self.inventory_table,
            "timeline": self.timeline_table,
            "chain": self.chain_table,
        }[table_name]
        table.setHorizontalHeaderLabels(labels)

    def export_timeline(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Export Timeline", str(Path.cwd() / "persistence-timeline.json"))
        if path:
            fmt = Path(path).suffix.lstrip(".") or "json"
            export_timeline(getattr(self, "timeline_events", []), fmt, path)

    def selected_finding_for_table(self, table: QTableWidget, items: list):
        rows = table.selectionModel().selectedRows()
        if not rows:
            return None
        row = rows[0].row()
        if row >= len(items):
            return None
        return items[row]

    def show_table_context_menu(self, table: QTableWidget, items: list, pos) -> None:
        finding = self.selected_finding_for_table(table, items)
        if not finding:
            return
        menu = QMenu(self)
        actions = [
            ("Copy Path", finding.path),
            ("Copy Command", finding.command),
            ("Copy SHA256", finding.sha256),
            ("Copy Team ID", team_id(finding)),
            ("Copy Bundle ID", str((finding.raw_evidence or {}).get("bundle_id") or (finding.raw_evidence or {}).get("bundleID") or "")),
        ]
        for label, value in actions:
            action = QAction(label, self)
            action.setEnabled(bool(value))
            action.triggered.connect(lambda _checked=False, selected=value: QApplication.clipboard().setText(selected))
            menu.addAction(action)
        reveal = QAction("Reveal in Finder", self)
        reveal.setEnabled(bool(finding.path and Path(finding.path).exists()))
        reveal.triggered.connect(lambda _checked=False, selected=finding.path: subprocess.Popen(["open", "-R", selected]))
        menu.addAction(reveal)
        menu.exec(table.viewport().mapToGlobal(pos))

    def open_logs_folder(self) -> None:
        log_dir = get_log_dir()
        log_dir.mkdir(parents=True, exist_ok=True)
        subprocess.Popen(["open", str(log_dir)])

    def update_scanner_diagnostics(self) -> None:
        lines = [
            f"Total inventory items: {len(self.inventory_items)}",
            f"Total findings: {len(self.findings)}",
            "",
            "Per-module counts:",
            *[f"- {name}: {count}" for name, count in self.scanner_counts.items()],
            "",
            "Warnings:",
            *([f"- {warning}" for warning in self.scanner_warnings] or ["- None"]),
            "",
            "Errors:",
            *([f"- {error}" for error in self.scanner_errors] or ["- None"]),
            "",
            "Active filters:",
            f"- Inventory mechanism={self.inventory_filter_bar.category.currentText()} MITRE={self.inventory_filter_bar.mitre.currentText()} severity={self.inventory_filter_bar.severity.currentText()}",
            f"- Findings mechanism={self.filter_bar.category.currentText()} MITRE={self.filter_bar.mitre.currentText()} severity={self.filter_bar.severity.currentText()}",
        ]
        self.scanner_diagnostics.setPlainText("\n".join(lines))

    def update_dashboard(self) -> None:
        while self.dashboard_grid.count():
            item = self.dashboard_grid.takeAt(0)
            widget = item.widget()
            if widget:
                widget.deleteLater()
        counts = Counter(str(item.severity) for item in self.inventory_items)
        unsigned = sum(1 for item in self.inventory_items if item.code_signature_status in {"unsigned", "invalid"})
        suspicious = sum(1 for item in self.inventory_items if "Risk factors:" in item.explanation)
        world_writable = sum(1 for item in self.inventory_items if item.raw_evidence.get("world_writable_plist"))
        mitre = len({item.mitre_technique_id for item in self.inventory_items if item.mitre_technique_id})
        new_count = len(self.baseline_diff.added)
        cards = [
            ("Security Posture", str(getattr(self, "posture", {}).get("score", 100)), getattr(self, "posture", {}).get("grade", "Not scanned")),
            ("Total Persistence Items", str(len(self.inventory_items)), "All observed persistence indicators"),
            ("New Since Baseline", str(new_count), "Added after selected baseline"),
            ("Critical Findings", str(counts["CRITICAL"]), "Click to view critical items"),
            ("High Findings", str(counts["HIGH"]), "Click to view high severity items"),
            ("Unsigned Items", str(unsigned), "Click to view unsigned/invalid items"),
            ("Suspicious Commands", str(suspicious), "Downloader, interpreter, or URL risk factors"),
            ("World-Writable References", str(world_writable), "Writable path indicators"),
            ("MITRE Techniques Observed", str(mitre), "Mapped ATT&CK techniques"),
            ("Last Scan Time", self.last_scan_time or "Never", "UTC timestamp"),
        ]
        for index, (title, value, detail) in enumerate(cards):
            card = StatCard(title, value, detail)
            if title == "Critical Findings":
                card.mousePressEvent = lambda _event: self.open_findings_preset(severity="CRITICAL", sort=[("severity", False), ("risk_score", False)])
            elif title == "High Findings":
                card.mousePressEvent = lambda _event: self.open_findings_preset(severity="HIGH", sort=[("severity", False), ("risk_score", False)])
            elif title == "New Since Baseline":
                card.mousePressEvent = lambda _event: self.open_findings_preset(only_new=True, sort=[("new", False), ("severity", False)])
            elif title == "Unsigned Items":
                card.mousePressEvent = lambda _event: self.open_findings_preset(sort=[("signing", True), ("severity", False)])
            self.dashboard_grid.addWidget(card, index // 4, index % 4)
        self.update_heatmap()
        diagnostics = [
            f"Total inventory items: {len(self.inventory_items)}",
            f"Total findings: {len(self.findings)}",
            "Scanner counts:",
            *[f"- {name}: {count}" for name, count in self.scanner_counts.items()],
            "Scanner warnings:",
            *([f"- {warning}" for warning in self.scanner_warnings] or ["- None"]),
            "Scanner errors:",
            *([f"- {error}" for error in self.scanner_errors] or ["- None"]),
            "Active filters:",
            f"- Inventory severity={self.inventory_filter_bar.severity.currentText()} category={self.inventory_filter_bar.category.currentText()} mitre={self.inventory_filter_bar.mitre.currentText()} show_info={self.inventory_filter_bar.show_info.isChecked()}",
            f"- Findings severity={self.filter_bar.severity.currentText()} category={self.filter_bar.category.currentText()} mitre={self.filter_bar.mitre.currentText()} show_info={self.filter_bar.show_info.isChecked()}",
        ]
        if not self.inventory_items:
            diagnostics.extend(
                [
                    "",
                    "No inventory was discovered. Common causes:",
                    "- The app lacks permission to read scanner paths.",
                    "- The selected root path does not contain macOS persistence directories.",
                    "- Filters are hiding normal INFO items.",
                    "- A scanner error occurred before reading target paths.",
                ]
            )
        self.diagnostics_box.setPlainText("\n".join(diagnostics))

    def open_findings_preset(self, severity: str | None = None, only_new: bool = False, search: str = "", sort: list[tuple[str, bool]] | None = None) -> None:
        self.sidebar.setCurrentRow(2)
        self.filter_bar.reset()
        if severity:
            self.filter_bar.severity.setCurrentText(severity)
        if only_new:
            self.filter_bar.only_new.setChecked(True)
        if search:
            self.filter_bar.search.setText(search)
        if sort:
            self.findings_sort = sort
        self.apply_filters()

    def update_heatmap(self) -> None:
        severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        mechanisms = sorted({item.category for item in self.inventory_items})
        self.heatmap_table.setRowCount(len(mechanisms))
        for row, mechanism in enumerate(mechanisms):
            self.heatmap_table.setItem(row, 0, QTableWidgetItem(mechanism))
            for col, severity in enumerate(severities, start=1):
                count = sum(1 for item in self.inventory_items if item.category == mechanism and str(item.severity) == severity)
                cell = QTableWidgetItem(str(count))
                cell.setTextAlignment(Qt.AlignCenter)
                self.heatmap_table.setItem(row, col, cell)
        self.heatmap_table.resizeColumnsToContents()

    def apply_filters(self) -> None:
        source = self.inventory_items if self.filter_bar.show_info.isChecked() else self.findings
        self.filtered_findings = self._filter_items(source, self.filter_bar)
        self.filtered_findings = sort_items(self.filtered_findings, self.findings_sort, self.finding_key_map())
        self.populate_table()

    def apply_inventory_filters(self) -> None:
        self.filtered_inventory = self._filter_items(self.inventory_items, self.inventory_filter_bar)
        self.filtered_inventory = sort_items(self.filtered_inventory, self.inventory_sort, self.inventory_key_map())
        self.populate_inventory_table()

    def _filter_items(self, source: list, filter_bar: FilterBar) -> list:
        severity = filter_bar.severity.currentText()
        category = filter_bar.category.currentText()
        mitre = filter_bar.mitre.currentText()
        query = filter_bar.search.text().lower().strip()
        new_ids = {item.id for item in self.baseline_diff.added}
        threshold_order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        threshold = self.threshold_setting.currentText() if hasattr(self, "threshold_setting") else "INFO"
        threshold_index = threshold_order.index(threshold)
        filtered = []
        for item in source:
            haystack = " ".join([item.title, item.category, item.path, item.executable_path, item.command]).lower()
            if not filter_bar.show_info.isChecked() and str(item.severity) == "INFO":
                continue
            if severity != "All" and str(item.severity) != severity:
                continue
            if category != "All" and item.category != category:
                continue
            if mitre != "All" and item.mitre_technique_id != mitre:
                continue
            if query and query not in haystack:
                continue
            if filter_bar.only_new.isChecked() and item.id not in new_ids:
                continue
            if threshold_order.index(str(item.severity)) < threshold_index:
                continue
            filtered.append(item)
        return filtered

    def populate_inventory_table(self) -> None:
        self.inventory_table.setRowCount(len(self.filtered_inventory))
        for row, finding in enumerate(self.filtered_inventory):
            self.inventory_table.setCellWidget(row, 0, SeverityBadge(str(finding.severity)))
            trust = (finding.raw_evidence or {}).get("trust", {})
            values = [
                finding.category,
                finding.title,
                finding.category,
                finding.owner,
                team_id(finding),
                finding.created_time,
                finding.modified_time,
                finding.first_seen,
                finding.last_seen,
                str(trust.get("score", 0)),
                finding.path,
            ]
            for col, value in enumerate(values, start=1):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                self.inventory_table.setItem(row, col, item)
        self.inventory_table.resizeColumnsToContents()
        self.update_header_labels("inventory")
        empty = not self.filtered_inventory
        self.inventory_empty.setVisible(empty)
        self.inventory_table.setVisible(not empty)
        if empty:
            self.inventory_detail_panel.show_empty()

    def populate_table(self) -> None:
        self.table.setRowCount(len(self.filtered_findings))
        new_ids = {item.id for item in self.baseline_diff.added}
        for row, finding in enumerate(self.filtered_findings):
            self.table.setCellWidget(row, 0, SeverityBadge(str(finding.severity)))
            trust = (finding.raw_evidence or {}).get("trust", {})
            values = [
                finding.title,
                finding.category,
                finding.mitre_technique_id,
                str(risk_score(finding)),
                str(trust.get("score", 0)),
                finding.first_seen,
                finding.last_seen,
                finding.path,
                team_id(finding),
                finding.code_signature_status,
                "New persistence item" if finding.id in new_ids else "",
            ]
            for col, value in enumerate(values, start=1):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                self.table.setItem(row, col, item)
        self.table.resizeColumnsToContents()
        self.update_header_labels("findings")
        empty = not self.filtered_findings
        self.findings_empty.setVisible(empty)
        self.table.setVisible(not empty)
        if empty:
            self.detail_panel.show_empty()

    def show_selected_detail(self) -> None:
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return
        finding = self.filtered_findings[rows[0].row()]
        self.detail_panel.set_finding(finding, finding.id in {item.id for item in self.baseline_diff.added})

    def show_selected_inventory_detail(self) -> None:
        rows = self.inventory_table.selectionModel().selectedRows()
        if not rows:
            return
        finding = self.filtered_inventory[rows[0].row()]
        self.inventory_detail_panel.set_finding(finding, finding.id in {item.id for item in self.baseline_diff.added})

    def create_baseline(self) -> None:
        if not self.inventory_items:
            QMessageBox.information(self, "Create Baseline", "Run a scan before creating a baseline.")
            return
        name = f"baseline-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        db = RadarDatabase()
        db.save_snapshot(name, self.inventory_items, utc_now_iso())
        db.close()
        self.baseline_summary.setText(f"Created baseline '{name}' with {len(self.inventory_items)} items.")

    def compare_baseline(self) -> None:
        db = RadarDatabase()
        snapshots = db.list_snapshots()
        if not snapshots:
            db.close()
            QMessageBox.information(self, "Compare Baseline", "No saved baselines are available.")
            return
        name = snapshots[0]["name"]
        self.baseline_findings = db.load_snapshot(name)
        db.close()
        self.baseline_diff = compare_findings(self.baseline_findings, self.inventory_items)
        apply_trust(self.inventory_items, baseline_ids={item.id for item in self.baseline_findings})
        self.findings = [item for item in self.inventory_items if str(item.severity) != "INFO"]
        self.timeline_events = events_from_diff(self.baseline_diff)
        self.baseline_summary.setText(
            f"Compared against '{name}': added {len(self.baseline_diff.added)}, "
            f"removed {len(self.baseline_diff.removed)}, modified {len(self.baseline_diff.modified)}."
        )
        self.baseline_changes.setPlainText(self._diff_text(self.baseline_diff))
        self.update_all_views()

    def _diff_text(self, diff: BaselineDiff) -> str:
        lines = ["Added"]
        lines.extend([f"- {item.title} ({item.path})" for item in diff.added] or ["- None"])
        lines.append("\nRemoved")
        lines.extend([f"- {item.title} ({item.path})" for item in diff.removed] or ["- None"])
        lines.append("\nModified")
        lines.extend([f"- {old.title} ({old.path})" for old, _new in diff.modified] or ["- None"])
        return "\n".join(lines)

    def start_watch(self) -> None:
        self.watch_timer.start(self.watch_interval.value() * 1000)
        self.watch_status.setText("Running")
        self.watch_status.setObjectName("StatusRunning")
        self.watch_status.style().unpolish(self.watch_status)
        self.watch_status.style().polish(self.watch_status)
        self.start_scan()

    def stop_watch(self) -> None:
        self.watch_timer.stop()
        self.watch_status.setText("Stopped")
        self.watch_status.setObjectName("StatusStopped")
        self.watch_status.style().unpolish(self.watch_status)
        self.watch_status.style().polish(self.watch_status)

    def export(self, fmt: str) -> None:
        folder = Path(self.export_folder.text()) if hasattr(self, "export_folder") else Path.cwd()
        default = folder / f"persistence-radar-report.{fmt}"
        path, _ = QFileDialog.getSaveFileName(self, f"Export {fmt.upper()}", str(default))
        if path:
            try:
                export_report(self.inventory_items, fmt, path, self.scanner_warnings, self.scanner_errors)
            except Exception as exc:
                QMessageBox.critical(self, "Export Failed", str(exc))

    def choose_export_folder(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Choose Export Folder", self.export_folder.text())
        if path:
            self.export_folder.setText(path)

    def apply_theme(self, theme: str) -> None:
        if theme == "Light":
            self.setStyleSheet(LIGHT_STYLE)
        else:
            self.setStyleSheet(DARK_STYLE)


DARK_STYLE = """
QMainWindow, QWidget { background: #0f141b; color: #dbe4ef; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI"; font-size: 13px; }
#Sidebar { background: #111923; border: 0; padding: 12px; }
#Sidebar::item { padding: 12px 14px; border-radius: 8px; margin: 2px 6px; }
#Sidebar::item:selected { background: #263445; color: #ffffff; }
#PageTitle { font-size: 24px; font-weight: 700; color: #f4f7fb; }
#PanelTitle, #EmptyTitle { font-size: 17px; font-weight: 700; color: #f4f7fb; }
#MutedLabel { color: #94a3b8; }
#StatCard, #DetailPanel, #EmptyState { background: #151d27; border: 1px solid #273244; border-radius: 8px; }
#StatValue { font-size: 27px; font-weight: 750; color: #ffffff; }
QPushButton { background: #2563eb; color: #ffffff; border: 0; border-radius: 6px; padding: 8px 13px; font-weight: 650; }
QPushButton:hover { background: #1d4ed8; }
QLineEdit, QComboBox, QSpinBox, QTextEdit { background: #111923; color: #dbe4ef; border: 1px solid #2c3a4e; border-radius: 6px; padding: 7px; }
QTableWidget { background: #111923; alternate-background-color: #151d27; gridline-color: #273244; border: 1px solid #273244; border-radius: 8px; }
QHeaderView::section { background: #182232; color: #cbd5e1; border: 0; padding: 9px; font-weight: 700; }
QTableWidget::item { padding: 8px; }
QProgressBar { max-width: 180px; }
#StatusRunning { color: #86efac; font-weight: 700; }
#StatusStopped { color: #fca5a5; font-weight: 700; }
#ErrorBox { border-color: #7a2d12; }
"""

LIGHT_STYLE = """
QMainWindow, QWidget { background: #f6f8fb; color: #17202a; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI"; font-size: 13px; }
#Sidebar { background: #ffffff; border-right: 1px solid #d8e0ea; padding: 12px; }
#Sidebar::item { padding: 12px 14px; border-radius: 8px; margin: 2px 6px; }
#Sidebar::item:selected { background: #e8f0ff; color: #102a5c; }
#PageTitle { font-size: 24px; font-weight: 700; color: #101820; }
#PanelTitle, #EmptyTitle { font-size: 17px; font-weight: 700; color: #101820; }
#MutedLabel { color: #66758a; }
#StatCard, #DetailPanel, #EmptyState { background: #ffffff; border: 1px solid #d8e0ea; border-radius: 8px; }
#StatValue { font-size: 27px; font-weight: 750; color: #101820; }
QPushButton { background: #2563eb; color: #ffffff; border: 0; border-radius: 6px; padding: 8px 13px; font-weight: 650; }
QLineEdit, QComboBox, QSpinBox, QTextEdit { background: #ffffff; color: #17202a; border: 1px solid #cbd5e1; border-radius: 6px; padding: 7px; }
QTableWidget { background: #ffffff; gridline-color: #d8e0ea; border: 1px solid #d8e0ea; border-radius: 8px; }
QHeaderView::section { background: #eef2f7; color: #334155; border: 0; padding: 9px; font-weight: 700; }
QTableWidget::item { padding: 8px; }
#StatusRunning { color: #15803d; font-weight: 700; }
#StatusStopped { color: #b91c1c; font-weight: 700; }
"""


def main() -> int:
    setup_logging()
    install_global_exception_hook()
    app = QApplication(sys.argv)
    app.setApplicationName("macOS Persistence Radar")
    app.setApplicationDisplayName("macOS Persistence Radar")
    app.setWindowIcon(app_icon())
    window = RadarWindow()
    window.show()
    return app.exec()

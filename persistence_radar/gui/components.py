from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from persistence_radar.core.reporting import risk_factors, verification_commands

SEVERITY_COLORS = {
    "CRITICAL": ("#5f121b", "#ffd8de"),
    "HIGH": ("#7a2d12", "#ffe0cf"),
    "MEDIUM": ("#6a5313", "#fff0bd"),
    "LOW": ("#173f2a", "#caf7dc"),
    "INFO": ("#173955", "#d4ebff"),
}


class SeverityBadge(QLabel):
    def __init__(self, severity: str) -> None:
        super().__init__(severity)
        background, foreground = SEVERITY_COLORS.get(severity, ("#2b3440", "#dce4ee"))
        self.setAlignment(Qt.AlignCenter)
        self.setMinimumWidth(82)
        self.setStyleSheet(
            "QLabel {"
            f"background: {background}; color: {foreground};"
            "border-radius: 10px; padding: 3px 9px; font-weight: 700; font-size: 11px;"
            "}"
        )


class StatCard(QFrame):
    def __init__(self, title: str, value: str, detail: str = "") -> None:
        super().__init__()
        self.setObjectName("StatCard")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(6)
        title_label = QLabel(title)
        title_label.setObjectName("MutedLabel")
        value_label = QLabel(value)
        value_label.setObjectName("StatValue")
        detail_label = QLabel(detail)
        detail_label.setObjectName("MutedLabel")
        detail_label.setWordWrap(True)
        layout.addWidget(title_label)
        layout.addWidget(value_label)
        if detail:
            layout.addWidget(detail_label)


class EmptyStateWidget(QFrame):
    def __init__(self, title: str, message: str, action: QPushButton | None = None) -> None:
        super().__init__()
        self.setObjectName("EmptyState")
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignCenter)
        layout.setSpacing(10)
        title_label = QLabel(title)
        title_label.setObjectName("EmptyTitle")
        message_label = QLabel(message)
        message_label.setObjectName("MutedLabel")
        message_label.setWordWrap(True)
        message_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_label)
        layout.addWidget(message_label)
        if action:
            layout.addWidget(action, alignment=Qt.AlignCenter)


class FilterBar(QWidget):
    def __init__(self) -> None:
        super().__init__()
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search findings, paths, commands")
        self.severity = QComboBox()
        self.severity.addItems(["All", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
        self.category = QComboBox()
        self.category.addItem("All")
        self.mitre = QComboBox()
        self.mitre.addItem("All")
        self.only_new = QCheckBox("Only new since baseline")
        self.show_info = QCheckBox("Show INFO / normal items")
        self.show_info.setChecked(True)
        self.reset_button = QPushButton("Reset Filters")
        for label, widget in (
            ("Search", self.search),
            ("Severity", self.severity),
            ("Category", self.category),
            ("MITRE", self.mitre),
        ):
            text = QLabel(label)
            text.setObjectName("MutedLabel")
            layout.addWidget(text)
            layout.addWidget(widget)
        layout.addWidget(self.only_new)
        layout.addWidget(self.show_info)
        layout.addWidget(self.reset_button)

    def connect_changed(self, slot) -> None:
        self.search.textChanged.connect(slot)
        self.severity.currentTextChanged.connect(slot)
        self.category.currentTextChanged.connect(slot)
        self.mitre.currentTextChanged.connect(slot)
        self.only_new.stateChanged.connect(slot)
        self.show_info.stateChanged.connect(slot)
        self.reset_button.clicked.connect(self.reset)
        self.reset_button.clicked.connect(slot)

    def reset(self) -> None:
        self.search.clear()
        self.severity.setCurrentText("All")
        self.category.setCurrentText("All")
        self.mitre.setCurrentText("All")
        self.only_new.setChecked(False)
        self.show_info.setChecked(True)

    def set_values(self, categories: list[str], mitre_ids: list[str]) -> None:
        current_category = self.category.currentText()
        current_mitre = self.mitre.currentText()
        self.category.blockSignals(True)
        self.mitre.blockSignals(True)
        self.category.clear()
        self.mitre.clear()
        self.category.addItems(["All"] + categories)
        self.mitre.addItems(["All"] + mitre_ids)
        self.category.setCurrentText(current_category if current_category in categories else "All")
        self.mitre.setCurrentText(current_mitre if current_mitre in mitre_ids else "All")
        self.category.blockSignals(False)
        self.mitre.blockSignals(False)


class FindingDetailPanel(QFrame):
    def __init__(self) -> None:
        super().__init__()
        self.setObjectName("DetailPanel")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(12)
        self.title = QLabel("Select a finding")
        self.title.setObjectName("PanelTitle")
        self.body = QTextEdit()
        self.body.setReadOnly(True)
        self.body.setObjectName("DetailText")
        layout.addWidget(self.title)
        layout.addWidget(self.body, 1)
        self.show_empty()

    def show_empty(self) -> None:
        self.title.setText("Select a finding")
        self.body.setPlainText("Choose a row to view the explanation, evidence, MITRE mapping, and verification commands.")

    def set_finding(self, finding, is_new: bool = False) -> None:
        self.title.setText(finding.title + ("  [NEW]" if is_new else ""))
        factors = risk_factors(finding)
        factor_text = "\n".join(f"- {factor}" for factor in factors) or "- No elevated risk factors were identified by the current rules."
        commands = "\n".join(verification_commands(finding)) or "No specific verification commands generated."
        trust = (finding.raw_evidence or {}).get("trust", {})
        positives = "\n".join(f"- {item}" for item in trust.get("positive_indicators", [])) or "- None observed"
        negatives = "\n".join(f"- {item}" for item in trust.get("negative_indicators", [])) or "- None observed"
        neutral = "\n".join(f"- {item}" for item in trust.get("neutral_indicators", [])) or "- None"
        trust_text = f"""Trust Breakdown
Reputation: {trust.get("score", "unknown")}/100
Classification: {trust.get("classification", "Unknown")}
Confidence: {trust.get("confidence", "Low")}
Why: {trust.get("why", "Trust has not been calculated for this item.")}

Positive indicators
{positives}

Negative indicators
{negatives}

Neutral indicators
{neutral}
"""
        why = (
            "Persistence items can cause software to start automatically. That is normal for many legitimate tools, "
            "but suspicious location, signing, ownership, or command behavior can indicate unauthorized persistence."
        )
        text = f"""Plain-English summary
{finding.explanation}

{trust_text}

Why this matters
{why}

Evidence
- File path: {finding.path}
- Executable path: {finding.executable_path or "not specified"}
- Command: {finding.command or "not specified"}
- Owner: {finding.owner or "unknown"}
- Permissions: {finding.permissions or "unknown"}
- SHA256: {finding.sha256 or "not available"}
- Code signing status: {finding.code_signature_status}
- First seen: {finding.first_seen}
- Last seen: {finding.last_seen}

MITRE mapping
{finding.mitre_technique_id or "Unmapped"} {finding.mitre_technique_name}

Risk factors
{factor_text}

Recommendation
{finding.recommendation}

Suggested verification commands
{commands}

Raw evidence
{finding.raw_evidence}
"""
        self.body.setPlainText(text)


class KeyValueGrid(QWidget):
    def __init__(self, rows: list[tuple[str, QWidget]]) -> None:
        super().__init__()
        layout = QGridLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setHorizontalSpacing(14)
        layout.setVerticalSpacing(10)
        for row, (label, widget) in enumerate(rows):
            label_widget = QLabel(label)
            label_widget.setObjectName("MutedLabel")
            layout.addWidget(label_widget, row, 0)
            layout.addWidget(widget, row, 1)

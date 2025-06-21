"""
Unit tests for monitoring functionality.
"""

import pytest
from datetime import datetime, timedelta
from shield.monitoring.threat_monitor import ThreatMonitor, ThreatEvent, AlertLevel


class TestThreatMonitor:
    """Test cases for ThreatMonitor class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.monitor = ThreatMonitor()

    def test_threat_monitor_initialization(self):
        """Test ThreatMonitor initializes correctly."""
        assert self.monitor is not None
        assert hasattr(self.monitor, "log_detection")
        assert hasattr(self.monitor, "get_statistics")

    def test_log_detection(self):
        """Test logging detection events."""
        self.monitor.log_detection(
            event_type="test_threat",
            content="test content",
            is_threat=True,
            risk_score=0.8,
        )

        stats = self.monitor.get_statistics()
        assert stats["total_events"] >= 1
        assert stats["threat_events"] >= 1

    def test_statistics_structure(self):
        """Test statistics return structure."""
        stats = self.monitor.get_statistics()

        assert "total_events" in stats
        assert "threat_events" in stats
        assert "threat_rate" in stats
        assert "active_alerts" in stats

    def test_safe_event_logging(self):
        """Test logging safe events."""
        self.monitor.log_detection(
            event_type="safe_request",
            content="hello world",
            is_threat=False,
            risk_score=0.1,
        )

        stats = self.monitor.get_statistics()
        assert stats["total_events"] >= 1

    def test_threat_event_structure(self):
        """Test ThreatEvent structure."""
        event = ThreatEvent(
            timestamp=datetime.utcnow(),
            event_type="test",
            content="test content",
            is_threat=True,
            risk_score=0.8,
        )

        assert event.timestamp is not None
        assert event.event_type == "test"
        assert event.is_threat is True
        assert event.risk_score == 0.8

    def test_alert_level_enum(self):
        """Test AlertLevel enum values."""
        assert AlertLevel.LOW.value == "low"
        assert AlertLevel.MEDIUM.value == "medium"
        assert AlertLevel.HIGH.value == "high"
        assert AlertLevel.CRITICAL.value == "critical"

"""
Threat monitoring module for real-time security monitoring and alerting.
Provides operational security with threat detection tracking and analysis.
"""

import logging
import time
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from collections import defaultdict, deque
import json
import threading
from enum import Enum

logger = logging.getLogger(__name__)


class AlertLevel(Enum):
    """Alert severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ThreatEvent:
    """Individual threat detection event."""

    timestamp: datetime
    event_type: str
    content: str
    is_threat: bool
    risk_score: float
    source_ip: Optional[str] = None
    user_id: Optional[str] = None
    model_name: Optional[str] = None
    detection_method: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class SecurityAlert:
    """Security alert generated from threat events."""

    alert_id: str
    level: AlertLevel
    title: str
    description: str
    timestamp: datetime
    event_count: int
    related_events: List[str]
    is_active: bool = True
    resolved_timestamp: Optional[datetime] = None
    metadata: Optional[Dict[str, Any]] = None


class ThreatMonitor:
    """
    Real-time threat monitoring and alerting system.

    Tracks security events, generates alerts, and provides
    operational visibility into LLM security status.
    """

    def __init__(self, config: Optional[Dict] = None):
        # Alert thresholds
        self.alert_thresholds = {
            "high_risk_rate": 0.1,  # >10% high-risk events triggers alert
            "threat_spike": 5,  # 5+ threats in short period
            "repeated_attacks": 3,  # Same pattern 3+ times
            "critical_risk": 0.9,  # Individual event risk > 0.9
        }

        self.config = config or self._default_config()

        # Event storage (in production, use proper database)
        self.events = deque(maxlen=self.config.get("max_events", 10000))
        self.alerts = deque(maxlen=self.config.get("max_alerts", 1000))

        # Statistics tracking
        self.stats = {
            "total_events": 0,
            "threat_events": 0,
            "alerts_generated": 0,
            "active_alerts": 0,
            "avg_risk_score": 0.0,
            "events_by_type": defaultdict(int),
            "threats_by_hour": defaultdict(int),
            "top_attack_patterns": defaultdict(int),
        }

        # Background monitoring
        self._monitoring_active = True
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()

    def log_detection(
        self,
        event_type: str,
        content: str,
        is_threat: bool,
        risk_score: float,
        **metadata,
    ):
        """Log a threat detection event."""
        event = ThreatEvent(
            timestamp=datetime.utcnow(),
            event_type=event_type,
            content=content[:500],  # Truncate long content
            is_threat=is_threat,
            risk_score=risk_score,
            metadata=metadata,
        )

        self.events.append(event)
        self._update_statistics(event)

        # Check for immediate alerts
        self._check_alert_conditions(event)

        logger.info(
            f"Logged {event_type} event: threat={is_threat}, risk={risk_score:.3f}"
        )

    def get_statistics(self, time_window: Optional[timedelta] = None) -> Dict[str, Any]:
        """Get threat monitoring statistics."""
        if time_window:
            cutoff_time = datetime.utcnow() - time_window
            relevant_events = [e for e in self.events if e.timestamp >= cutoff_time]
        else:
            relevant_events = list(self.events)

        if not relevant_events:
            return self._empty_stats()

        total_events = len(relevant_events)
        threat_events = sum(1 for e in relevant_events if e.is_threat)
        avg_risk = sum(e.risk_score for e in relevant_events) / total_events

        # Event type breakdown
        event_types = defaultdict(int)
        for event in relevant_events:
            event_types[event.event_type] += 1

        # Hourly threat distribution
        hourly_threats = defaultdict(int)
        for event in relevant_events:
            if event.is_threat:
                hour_key = event.timestamp.strftime("%Y-%m-%d %H:00")
                hourly_threats[hour_key] += 1

        return {
            "total_events": total_events,
            "threat_events": threat_events,
            "threat_rate": threat_events / total_events if total_events > 0 else 0.0,
            "average_risk_score": avg_risk,
            "active_alerts": len([a for a in self.alerts if a.is_active]),
            "event_types": dict(event_types),
            "hourly_threats": dict(hourly_threats),
            "time_window": str(time_window) if time_window else "all_time",
            "last_updated": datetime.utcnow().isoformat(),
        }

    def get_active_alerts(self) -> List[Dict[str, Any]]:
        """Get list of active security alerts."""
        active_alerts = [a for a in self.alerts if a.is_active]
        return [asdict(alert) for alert in active_alerts]

    def resolve_alert(self, alert_id: str) -> bool:
        """Mark an alert as resolved."""
        for alert in self.alerts:
            if alert.alert_id == alert_id and alert.is_active:
                alert.is_active = False
                alert.resolved_timestamp = datetime.utcnow()
                logger.info(f"Resolved alert: {alert_id}")
                return True
        return False

    def get_threat_trends(self, hours: int = 24) -> Dict[str, Any]:
        """Analyze threat trends over specified time period."""
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        recent_events = [e for e in self.events if e.timestamp >= cutoff_time]

        if not recent_events:
            return {"trend": "no_data", "events_analyzed": 0}

        # Calculate trends
        hourly_counts = defaultdict(int)
        hourly_risks = defaultdict(list)

        for event in recent_events:
            hour_key = event.timestamp.hour
            hourly_counts[hour_key] += 1
            if event.is_threat:
                hourly_risks[hour_key].append(event.risk_score)

        # Determine trend direction
        recent_half = list(hourly_counts.values())[-12:]  # Last 12 hours
        earlier_half = list(hourly_counts.values())[:-12]  # Earlier 12 hours

        recent_avg = sum(recent_half) / len(recent_half) if recent_half else 0
        earlier_avg = sum(earlier_half) / len(earlier_half) if earlier_half else 0

        if recent_avg > earlier_avg * 1.2:
            trend = "increasing"
        elif recent_avg < earlier_avg * 0.8:
            trend = "decreasing"
        else:
            trend = "stable"

        return {
            "trend": trend,
            "events_analyzed": len(recent_events),
            "recent_average": recent_avg,
            "earlier_average": earlier_avg,
            "hourly_distribution": dict(hourly_counts),
            "peak_risk_hours": [
                h for h, risks in hourly_risks.items() if risks and max(risks) > 0.8
            ],
        }

    def generate_report(self, format: str = "json") -> str:
        """Generate comprehensive monitoring report."""
        stats = self.get_statistics()
        alerts = self.get_active_alerts()
        trends = self.get_threat_trends()

        report_data = {
            "report_timestamp": datetime.utcnow().isoformat(),
            "summary": {
                "total_events": stats["total_events"],
                "threat_events": stats["threat_events"],
                "threat_rate": stats["threat_rate"],
                "active_alerts": len(alerts),
                "trend": trends["trend"],
            },
            "detailed_statistics": stats,
            "active_alerts": alerts,
            "threat_trends": trends,
            "recommendations": self._generate_recommendations(stats, alerts, trends),
        }

        if format.lower() == "json":
            return json.dumps(report_data, indent=2, default=str)
        else:
            return self._format_text_report(report_data)

    def _update_statistics(self, event: ThreatEvent):
        """Update internal statistics with new event."""
        self.stats["total_events"] += 1
        self.stats["events_by_type"][event.event_type] += 1

        if event.is_threat:
            self.stats["threat_events"] += 1
            hour_key = event.timestamp.strftime("%Y-%m-%d %H")
            self.stats["threats_by_hour"][hour_key] += 1

        # Update rolling average risk score
        total_events = self.stats["total_events"]
        current_avg = self.stats["avg_risk_score"]
        self.stats["avg_risk_score"] = (
            (current_avg * (total_events - 1)) + event.risk_score
        ) / total_events

    def _check_alert_conditions(self, event: ThreatEvent):
        """Check if new event triggers any alert conditions."""
        # Critical individual risk
        if event.risk_score >= self.alert_thresholds["critical_risk"]:
            self._generate_alert(
                AlertLevel.CRITICAL,
                "Critical Risk Event Detected",
                f"Event with risk score {event.risk_score:.3f} detected: {event.event_type}",
                [event],
            )

        # Check for threat spikes (multiple threats in short time)
        recent_threats = [
            e
            for e in list(self.events)[-20:]
            if e.is_threat and (datetime.utcnow() - e.timestamp).total_seconds() < 300
        ]  # 5 minutes

        if len(recent_threats) >= self.alert_thresholds["threat_spike"]:
            self._generate_alert(
                AlertLevel.HIGH,
                "Threat Spike Detected",
                f"{len(recent_threats)} threats detected in the last 5 minutes",
                recent_threats,
            )

    def _generate_alert(
        self,
        level: AlertLevel,
        title: str,
        description: str,
        related_events: List[ThreatEvent],
    ):
        """Generate a new security alert."""
        alert_id = f"alert_{int(time.time())}_{len(self.alerts)}"

        alert = SecurityAlert(
            alert_id=alert_id,
            level=level,
            title=title,
            description=description,
            timestamp=datetime.utcnow(),
            event_count=len(related_events),
            related_events=[
                f"{e.event_type}_{e.timestamp.isoformat()}" for e in related_events
            ],
        )

        self.alerts.append(alert)
        self.stats["alerts_generated"] += 1
        self.stats["active_alerts"] = len([a for a in self.alerts if a.is_active])

        logger.warning(f"Generated {level.value} alert: {title}")

    def _monitor_loop(self):
        """Background monitoring loop for periodic checks."""
        while self._monitoring_active:
            try:
                # Periodic analysis every 5 minutes
                time.sleep(300)

                # Check for high threat rates
                recent_stats = self.get_statistics(timedelta(hours=1))
                if (
                    recent_stats["threat_rate"]
                    > self.alert_thresholds["high_risk_rate"]
                ):
                    self._generate_alert(
                        AlertLevel.MEDIUM,
                        "High Threat Rate Detected",
                        f"Threat rate of {recent_stats['threat_rate']:.1%} in the last hour",
                        [],
                    )

            except Exception as e:
                logger.error(f"Monitoring loop error: {e}")

    def _generate_recommendations(
        self, stats: Dict, alerts: List, trends: Dict
    ) -> List[str]:
        """Generate actionable recommendations based on monitoring data."""
        recommendations = []

        if stats["threat_rate"] > 0.05:  # >5% threat rate
            recommendations.append(
                "Consider tightening security thresholds due to high threat rate"
            )

        if len(alerts) > 5:
            recommendations.append(
                "Multiple active alerts - investigate potential coordinated attack"
            )

        if trends["trend"] == "increasing":
            recommendations.append(
                "Threat activity is increasing - consider enhanced monitoring"
            )

        if stats["average_risk_score"] > 0.3:
            recommendations.append(
                "Average risk score is elevated - review input validation"
            )

        if not recommendations:
            recommendations.append(
                "Security posture appears normal - continue monitoring"
            )

        return recommendations

    def _empty_stats(self) -> Dict[str, Any]:
        """Return empty statistics structure."""
        return {
            "total_events": 0,
            "threat_events": 0,
            "threat_rate": 0.0,
            "average_risk_score": 0.0,
            "active_alerts": 0,
            "event_types": {},
            "hourly_threats": {},
            "time_window": "no_data",
        }

    def _format_text_report(self, report_data: Dict) -> str:
        """Format report as human-readable text."""
        lines = [
            "=== SHIELD Threat Monitoring Report ===",
            f"Generated: {report_data['report_timestamp']}",
            "",
            "SUMMARY:",
            f"  Total Events: {report_data['summary']['total_events']}",
            f"  Threat Events: {report_data['summary']['threat_events']}",
            f"  Threat Rate: {report_data['summary']['threat_rate']:.1%}",
            f"  Active Alerts: {report_data['summary']['active_alerts']}",
            f"  Trend: {report_data['summary']['trend']}",
            "",
            "RECOMMENDATIONS:",
        ]

        for rec in report_data["recommendations"]:
            lines.append(f"  - {rec}")

        return "\n".join(lines)

    def _default_config(self) -> Dict[str, Any]:
        """Default monitoring configuration."""
        return {
            "max_events": 10000,
            "max_alerts": 1000,
            "alert_retention_hours": 168,  # 1 week
            "enable_background_monitoring": True,
            "alert_thresholds": self.alert_thresholds,
        }

    def shutdown(self):
        """Shutdown monitoring system."""
        self._monitoring_active = False
        if self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=5)
        logger.info("Threat monitoring system shutdown")

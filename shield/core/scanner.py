"""
Security scanning modules for input/output protection.
Inspired by LLM Guard's 35+ scanner approach.
"""

import re
import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class ThreatLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ScanResult:
    """Result of security scanning."""
    is_safe: bool
    threat_level: ThreatLevel
    violations: List[str]
    sanitized_content: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class BaseScanner:
    """Base class for all security scanners."""
    
    def __init__(self, enabled: bool = True):
        self.enabled = enabled
    
    def scan(self, content: str) -> ScanResult:
        """Scan content for security threats."""
        if not self.enabled:
            return ScanResult(True, ThreatLevel.LOW, [])
        return self._scan_implementation(content)
    
    def _scan_implementation(self, content: str) -> ScanResult:
        """Override in subclasses."""
        raise NotImplementedError


class PromptInjectionScanner(BaseScanner):
    """Detects prompt injection attacks."""
    
    def __init__(self, enabled: bool = True):
        super().__init__(enabled)
        self.injection_patterns = [
            r"ignore\s+previous\s+instructions",
            r"system\s*:\s*you\s+are",
            r"###\s*new\s+instructions",
            r"disregard\s+everything\s+above",
            r"\\u[0-9a-fA-F]{4}",  # Unicode escapes
            r"<\s*script.*?>",      # Script tags
        ]
    
    def _scan_implementation(self, content: str) -> ScanResult:
        """Scan for prompt injection patterns."""
        violations = []
        content_lower = content.lower()
        
        for pattern in self.injection_patterns:
            if re.search(pattern, content_lower, re.IGNORECASE):
                violations.append(f"Prompt injection pattern detected: {pattern}")
        
        threat_level = ThreatLevel.HIGH if violations else ThreatLevel.LOW
        return ScanResult(
            is_safe=len(violations) == 0,
            threat_level=threat_level,
            violations=violations,
            metadata={"scanner": "prompt_injection"}
        )


class SecurityScanner:
    """Comprehensive security scanner combining multiple detection methods."""
    
    def __init__(self):
        self.scanners = {
            "prompt_injection": PromptInjectionScanner(),
        }
    
    def scan_input(self, content: str) -> Dict[str, ScanResult]:
        """Scan input content with all enabled scanners."""
        results = {}
        for name, scanner in self.scanners.items():
            results[name] = scanner.scan(content)
        return results
    
    def scan_output(self, content: str) -> Dict[str, ScanResult]:
        """Scan output content with appropriate scanners."""
        # For output, we might want different scanner configurations
        output_scanners = ["prompt_injection"]  # Can be expanded
        results = {}
        for name in output_scanners:
            if name in self.scanners:
                results[name] = self.scanners[name].scan(content)
        return results
    
    def get_overall_result(self, scan_results: Dict[str, ScanResult]) -> ScanResult:
        """Combine results from multiple scanners."""
        all_violations = []
        max_threat_level = ThreatLevel.LOW
        is_safe = True
        
        for scanner_name, result in scan_results.items():
            all_violations.extend(result.violations)
            if result.threat_level.value == "critical":
                max_threat_level = ThreatLevel.CRITICAL
            elif result.threat_level.value == "high" and max_threat_level.value not in ["critical"]:
                max_threat_level = ThreatLevel.HIGH
            elif result.threat_level.value == "medium" and max_threat_level.value in ["low"]:
                max_threat_level = ThreatLevel.MEDIUM
            
            is_safe = is_safe and result.is_safe
        
        return ScanResult(
            is_safe=is_safe,
            threat_level=max_threat_level,
            violations=all_violations,
            metadata={"combined_results": True, "scanner_count": len(scan_results)}
        )


class MultiModalScanner:
    """Scanner for multi-modal inputs (text, images, audio)."""
    
    def __init__(self):
        self.text_scanner = SecurityScanner()
    
    def scan_multimodal(self, text: str = None, image_data: bytes = None, audio_data: bytes = None) -> Dict[str, Any]:
        """Scan multi-modal input."""
        results = {}
        
        if text:
            results["text"] = self.text_scanner.scan_input(text)
        
        if image_data:
            results["image"] = self._scan_image(image_data)
        
        if audio_data:
            results["audio"] = self._scan_audio(audio_data)
        
        return results
    
    def _scan_image(self, image_data: bytes) -> ScanResult:
        """Scan image for visual prompt injection."""
        # Placeholder for image analysis
        return ScanResult(True, ThreatLevel.LOW, [])
    
    def _scan_audio(self, audio_data: bytes) -> ScanResult:
        """Scan audio for adversarial content."""
        # Placeholder for audio analysis
        return ScanResult(True, ThreatLevel.LOW, []) 
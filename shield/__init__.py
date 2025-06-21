"""
SHIELD: Comprehensive LLM Adversarial Robustness Framework

A production-ready implementation of state-of-the-art LLM security techniques
based on 2024-2025 breakthrough research in adversarial robustness and jailbreak prevention.
"""

__version__ = "1.0.0"
__author__ = "San Hashim"
__email__ = "san.hashimhama@outlook.com"
__description__ = "Comprehensive LLM Adversarial Robustness Framework"

from .core.detector import GradientDetector, RefusalFeatureDetector
from .core.scanner import SecurityScanner, MultiModalScanner
from .monitoring.threat_monitor import ThreatMonitor
from .protection.input_guard import InputGuard
from .protection.output_guard import OutputGuard
from .evaluation.benchmarks import JailbreakBench, HarmBench
from .api.shield_api import ShieldAPI

__all__ = [
    # Core Detection
    "GradientDetector",
    "RefusalFeatureDetector",
    # Security Scanning
    "SecurityScanner",
    "MultiModalScanner",
    # Monitoring
    "ThreatMonitor",
    # Protection Guards
    "InputGuard",
    "OutputGuard",
    # Evaluation
    "JailbreakBench",
    "HarmBench",
    # API
    "ShieldAPI",
]

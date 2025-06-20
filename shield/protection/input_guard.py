"""
Input Guard module for comprehensive input protection.
Combines multiple detection and protection mechanisms.
"""

import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

from ..core.detector import GradientDetector, RefusalFeatureDetector, DetectionResult
from ..core.scanner import SecurityScanner, MultiModalScanner, ScanResult

logger = logging.getLogger(__name__)


@dataclass
class GuardResult:
    """Result of input guard processing."""
    is_safe: bool
    risk_score: float
    sanitized_input: Optional[str] = None
    violations: List[str] = None
    recommendations: List[str] = None
    metadata: Optional[Dict[str, Any]] = None


class InputGuard:
    """
    Comprehensive input protection system.
    
    Combines gradient-based detection, security scanning, and rule-based validation
    to provide layered defense against adversarial inputs.
    """
    
    def __init__(self, model=None, config: Optional[Dict] = None):
        self.model = model
        self.config = config or self._default_config()
        
        # Initialize detection components
        self.gradient_detector = GradientDetector(model) if model else None
        self.refusal_detector = RefusalFeatureDetector(model) if model else None
        self.security_scanner = SecurityScanner()
        self.multimodal_scanner = MultiModalScanner()
        
        # Risk scoring weights
        self.weights = {
            "gradient_detection": 0.3,
            "refusal_detection": 0.3,
            "security_scanning": 0.4
        }
    
    def protect(self, input_text: str, context: Optional[Dict] = None) -> GuardResult:
        """
        Comprehensive input protection with multi-layered analysis.
        
        Args:
            input_text: The input text to analyze
            context: Additional context for analysis
            
        Returns:
            GuardResult with protection assessment and recommendations
        """
        violations = []
        risk_scores = {}
        sanitized_input = input_text
        
        try:
            # Phase 1: Security Scanning
            scan_results = self.security_scanner.scan_input(input_text)
            overall_scan = self.security_scanner.get_overall_result(scan_results)
            
            if not overall_scan.is_safe:
                violations.extend(overall_scan.violations)
                # Use sanitized content if available
                for result in scan_results.values():
                    if result.sanitized_content:
                        sanitized_input = result.sanitized_content
                        break
            
            risk_scores["security_scanning"] = self._compute_scan_risk_score(overall_scan)
            
            # Phase 2: Gradient-based Detection (if model available)
            if self.gradient_detector and self.config.get("enable_gradient_detection", True):
                # Use a standard compliance response for gradient analysis
                compliance_response = "I cannot provide assistance with that request."
                detection_result = self.gradient_detector.detect(input_text, compliance_response)
                
                if detection_result.is_threat:
                    violations.append(f"Gradient anomaly detected: {detection_result.threat_type}")
                
                risk_scores["gradient_detection"] = detection_result.confidence_score
            
            # Phase 3: Refusal Feature Analysis (if model available)
            if self.refusal_detector and self.config.get("enable_refusal_detection", True):
                refusal_result = self.refusal_detector.detect(input_text, "")
                
                if refusal_result.is_threat:
                    violations.append(f"Refusal feature ablation detected")
                
                risk_scores["refusal_detection"] = refusal_result.confidence_score
            
            # Compute overall risk score
            overall_risk = self._compute_overall_risk(risk_scores)
            
            # Determine if input is safe
            is_safe = overall_risk < self.config.get("risk_threshold", 0.7) and len(violations) == 0
            
            # Generate recommendations
            recommendations = self._generate_recommendations(violations, risk_scores, overall_risk)
            
            return GuardResult(
                is_safe=is_safe,
                risk_score=overall_risk,
                sanitized_input=sanitized_input if sanitized_input != input_text else None,
                violations=violations,
                recommendations=recommendations,
                metadata={
                    "risk_scores": risk_scores,
                    "scan_results": scan_results,
                    "protection_layers": len([k for k, v in risk_scores.items() if v > 0])
                }
            )
            
        except Exception as e:
            logger.error(f"Input guard protection failed: {e}")
            return GuardResult(
                is_safe=False,
                risk_score=1.0,
                violations=[f"Protection system error: {str(e)}"],
                recommendations=["Contact system administrator"]
            )
    
    def protect_multimodal(self, text: str = None, image_data: bytes = None, audio_data: bytes = None) -> GuardResult:
        """Protect multi-modal inputs."""
        try:
            results = self.multimodal_scanner.scan_multimodal(text, image_data, audio_data)
            
            # Process text component if available
            if text:
                text_result = self.protect(text)
                return text_result
            
            # For non-text inputs, return basic analysis
            return GuardResult(
                is_safe=True,
                risk_score=0.1,
                violations=[],
                recommendations=[],
                metadata={"multimodal_results": results}
            )
            
        except Exception as e:
            logger.error(f"Multimodal protection failed: {e}")
            return GuardResult(is_safe=False, risk_score=1.0, violations=[str(e)])
    
    def _compute_scan_risk_score(self, scan_result: ScanResult) -> float:
        """Convert scan result to risk score."""
        if scan_result.threat_level.value == "critical":
            return 0.9
        elif scan_result.threat_level.value == "high":
            return 0.7
        elif scan_result.threat_level.value == "medium":
            return 0.5
        else:
            return 0.1
    
    def _compute_overall_risk(self, risk_scores: Dict[str, float]) -> float:
        """Compute weighted overall risk score."""
        total_score = 0.0
        total_weight = 0.0
        
        for component, score in risk_scores.items():
            weight = self.weights.get(component, 0.1)
            total_score += score * weight
            total_weight += weight
        
        return total_score / total_weight if total_weight > 0 else 0.0
    
    def _generate_recommendations(self, violations: List[str], risk_scores: Dict[str, float], overall_risk: float) -> List[str]:
        """Generate actionable recommendations based on analysis."""
        recommendations = []
        
        if overall_risk > 0.8:
            recommendations.append("Block this input - high risk detected")
        elif overall_risk > 0.5:
            recommendations.append("Review input manually before processing")
        
        if "pii" in str(violations):
            recommendations.append("Remove or anonymize PII before processing")
        
        if "prompt_injection" in str(violations):
            recommendations.append("Potential prompt injection - validate input structure")
        
        if risk_scores.get("gradient_detection", 0) > 0.7:
            recommendations.append("Gradient anomaly detected - potential adversarial input")
        
        if not recommendations:
            recommendations.append("Input appears safe for processing")
        
        return recommendations
    
    def _default_config(self) -> Dict[str, Any]:
        """Default configuration for input guard."""
        return {
            "risk_threshold": 0.7,
            "enable_gradient_detection": True,
            "enable_refusal_detection": True,
            "enable_pii_protection": True,
            "enable_prompt_injection_detection": True,
            "enable_toxicity_detection": True,
            "sanitize_pii": True,
            "block_high_risk": True
        }
    
    def update_config(self, new_config: Dict[str, Any]):
        """Update guard configuration."""
        self.config.update(new_config)
        logger.info(f"Updated input guard configuration: {new_config}")
    
    def calibrate(self, safe_inputs: List[str], unsafe_inputs: List[str]):
        """Calibrate detection thresholds using labeled examples."""
        if self.gradient_detector:
            # Create safe responses for calibration
            safe_responses = ["I'll help you with that." for _ in safe_inputs]
            self.gradient_detector.calibrate_baseline(safe_inputs, safe_responses)
        
        logger.info(f"Calibrated input guard with {len(safe_inputs)} safe and {len(unsafe_inputs)} unsafe examples") 
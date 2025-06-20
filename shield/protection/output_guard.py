"""
Output Guard module for filtering and validating model outputs.
Ensures outputs comply with safety and regulatory requirements.
"""

import logging
import re
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

from ..core.scanner import SecurityScanner, ScanResult

logger = logging.getLogger(__name__)


@dataclass
class OutputGuardResult:
    """Result of output guard processing."""
    is_safe: bool
    filtered_output: Optional[str] = None
    violations: List[str] = None
    compliance_score: float = 0.0
    metadata: Optional[Dict[str, Any]] = None


class OutputGuard:
    """
    Comprehensive output filtering and validation system.
    
    Ensures model outputs meet safety, privacy, and regulatory requirements
    before being delivered to users.
    """
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or self._default_config()
        self.security_scanner = SecurityScanner()
        
        # Compliance patterns for different regulations
        self.compliance_patterns = {
            "gdpr": {
                "data_subject_rights": r"(delete|remove|forget|erase).*personal.*data",
                "consent_language": r"(consent|permission|agree|authorize)",
                "privacy_terms": r"(privacy|confidential|personal.*information)"
            },
            "hipaa": {
                "health_info": r"(medical|health|patient|diagnosis|treatment)",
                "phi_identifiers": r"(medical.*record|patient.*id|health.*plan)"
            },
            "financial": {
                "pci_compliance": r"(credit.*card|payment|financial.*account)",
                "financial_advice": r"(investment.*advice|financial.*planning)"
            }
        }
    
    def filter(self, output_text: str, context: Optional[Dict] = None) -> OutputGuardResult:
        """
        Filter and validate model output for safety and compliance.
        
        Args:
            output_text: The model output to filter
            context: Additional context including regulations, user info, etc.
            
        Returns:
            OutputGuardResult with filtering assessment and sanitized output
        """
        violations = []
        filtered_output = output_text
        
        try:
            # Phase 1: Security scanning
            scan_results = self.security_scanner.scan_output(output_text)
            overall_scan = self.security_scanner.get_overall_result(scan_results)
            
            if not overall_scan.is_safe:
                violations.extend(overall_scan.violations)
                # Apply sanitization if available
                for result in scan_results.values():
                    if result.sanitized_content:
                        filtered_output = result.sanitized_content
                        break
            
            # Phase 2: Content policy validation
            policy_violations = self._check_content_policies(output_text)
            violations.extend(policy_violations)
            
            # Phase 3: Regulatory compliance checking
            compliance_violations = self._check_regulatory_compliance(output_text, context)
            violations.extend(compliance_violations)
            
            # Phase 4: Apply content filters
            filtered_output = self._apply_content_filters(filtered_output, violations)
            
            # Phase 5: Compute compliance score
            compliance_score = self._compute_compliance_score(violations, scan_results)
            
            # Determine if output is safe
            is_safe = len(violations) == 0 and compliance_score > self.config.get("min_compliance_score", 0.8)
            
            # Apply final safety measures
            if not is_safe and self.config.get("block_unsafe_outputs", True):
                filtered_output = self._generate_safe_response(violations)
            
            return OutputGuardResult(
                is_safe=is_safe,
                filtered_output=filtered_output if filtered_output != output_text else None,
                violations=violations,
                compliance_score=compliance_score,
                metadata={
                    "scan_results": scan_results,
                    "original_length": len(output_text),
                    "filtered_length": len(filtered_output),
                    "safety_measures_applied": not is_safe
                }
            )
            
        except Exception as e:
            logger.error(f"Output guard filtering failed: {e}")
            return OutputGuardResult(
                is_safe=False,
                filtered_output="I apologize, but I cannot provide a response at this time due to a system error.",
                violations=[f"Filtering system error: {str(e)}"],
                compliance_score=0.0
            )
    
    def _check_content_policies(self, output_text: str) -> List[str]:
        """Check output against content policies."""
        violations = []
        
        # Check for refusal bypass attempts in output
        refusal_bypass_patterns = [
            r"as\s+an\s+ai.*cannot",
            r"i'm\s+not\s+able\s+to",
            r"however.*i\s+can",
            r"but\s+here's\s+how"
        ]
        
        for pattern in refusal_bypass_patterns:
            if re.search(pattern, output_text.lower()):
                violations.append(f"Potential refusal bypass detected: {pattern}")
        
        # Check for inappropriate content generation
        if self._contains_inappropriate_content(output_text):
            violations.append("Inappropriate content detected in output")
        
        return violations
    
    def _check_regulatory_compliance(self, output_text: str, context: Optional[Dict]) -> List[str]:
        """Check output for regulatory compliance."""
        violations = []
        
        if not context:
            return violations
        
        required_regulations = context.get("regulations", [])
        
        for regulation in required_regulations:
            if regulation in self.compliance_patterns:
                patterns = self.compliance_patterns[regulation]
                
                for check_name, pattern in patterns.items():
                    if re.search(pattern, output_text.lower()):
                        # For certain patterns, this might be a violation
                        if regulation == "hipaa" and "health_info" in check_name:
                            violations.append(f"Potential HIPAA violation: health information in output")
                        elif regulation == "gdpr" and "personal" in pattern:
                            violations.append(f"Potential GDPR violation: personal data in output")
        
        return violations
    
    def _apply_content_filters(self, output_text: str, violations: List[str]) -> str:
        """Apply content filters based on detected violations."""
        filtered_text = output_text
        
        # Remove potential PII that might have been missed
        if any("pii" in v.lower() for v in violations):
            # Apply additional PII filtering
            filtered_text = self._filter_pii(filtered_text)
        
        # Remove potentially harmful instructions
        if any("injection" in v.lower() for v in violations):
            filtered_text = self._filter_instructions(filtered_text)
        
        return filtered_text
    
    def _filter_pii(self, text: str) -> str:
        """Apply additional PII filtering."""
        # Phone numbers
        text = re.sub(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', '[PHONE_REDACTED]', text)
        
        # Email addresses
        text = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[EMAIL_REDACTED]', text)
        
        # Credit card numbers
        text = re.sub(r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b', '[CARD_REDACTED]', text)
        
        return text
    
    def _filter_instructions(self, text: str) -> str:
        """Filter potentially harmful instructions."""
        # Remove system prompts that might have leaked through
        text = re.sub(r'System:\s*.*?\n', '', text, flags=re.IGNORECASE)
        
        # Remove instruction-like patterns
        text = re.sub(r'###\s*Instructions?:.*?\n', '', text, flags=re.IGNORECASE)
        
        return text
    
    def _contains_inappropriate_content(self, text: str) -> bool:
        """Check if output contains inappropriate content."""
        inappropriate_indicators = [
            "illegal activities",
            "harmful instructions",
            "personal information",
            "discriminatory content"
        ]
        
        text_lower = text.lower()
        return any(indicator in text_lower for indicator in inappropriate_indicators)
    
    def _compute_compliance_score(self, violations: List[str], scan_results: Dict[str, ScanResult]) -> float:
        """Compute overall compliance score."""
        base_score = 1.0
        
        # Deduct points for violations
        violation_penalty = len(violations) * 0.1
        
        # Deduct points for scan results
        scan_penalty = 0.0
        for result in scan_results.values():
            if not result.is_safe:
                if result.threat_level.value == "critical":
                    scan_penalty += 0.3
                elif result.threat_level.value == "high":
                    scan_penalty += 0.2
                elif result.threat_level.value == "medium":
                    scan_penalty += 0.1
        
        final_score = max(0.0, base_score - violation_penalty - scan_penalty)
        return final_score
    
    def _generate_safe_response(self, violations: List[str]) -> str:
        """Generate a safe response when output is blocked."""
        if any("pii" in v.lower() for v in violations):
            return "I apologize, but I cannot provide a response that might contain personal information."
        
        if any("inappropriate" in v.lower() for v in violations):
            return "I cannot provide that type of content. Please ask for something else I can help with."
        
        if any("compliance" in v.lower() for v in violations):
            return "I cannot provide a response that might violate regulatory requirements."
        
        return "I apologize, but I cannot provide that response. Please rephrase your request."
    
    def _default_config(self) -> Dict[str, Any]:
        """Default configuration for output guard."""
        return {
            "min_compliance_score": 0.8,
            "block_unsafe_outputs": True,
            "enable_pii_filtering": True,
            "enable_content_policy_checking": True,
            "enable_regulatory_compliance": True,
            "strict_mode": False  # If True, applies stricter filtering
        }
    
    def update_config(self, new_config: Dict[str, Any]):
        """Update guard configuration."""
        self.config.update(new_config)
        logger.info(f"Updated output guard configuration: {new_config}")
    
    def add_custom_filter(self, filter_name: str, pattern: str, replacement: str = "[REDACTED]"):
        """Add a custom content filter."""
        if "custom_filters" not in self.config:
            self.config["custom_filters"] = {}
        
        self.config["custom_filters"][filter_name] = {
            "pattern": pattern,
            "replacement": replacement
        }
        
        logger.info(f"Added custom filter: {filter_name}")
    
    def validate_compliance(self, output_text: str, regulations: List[str]) -> Dict[str, bool]:
        """Validate output against specific regulations."""
        compliance_status = {}
        
        for regulation in regulations:
            if regulation in self.compliance_patterns:
                # Check if output complies with regulation
                violations = self._check_regulatory_compliance(output_text, {"regulations": [regulation]})
                compliance_status[regulation] = len(violations) == 0
            else:
                compliance_status[regulation] = True  # Unknown regulations pass by default
        
        return compliance_status 
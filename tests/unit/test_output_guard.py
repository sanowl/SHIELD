"""
Unit tests for OutputGuard functionality.
"""

import pytest
from shield.protection.output_guard import OutputGuard, OutputGuardResult


class TestOutputGuard:
    """Test cases for OutputGuard class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.guard = OutputGuard()

    def test_output_guard_initialization(self):
        """Test OutputGuard initializes correctly."""
        assert self.guard is not None
        assert hasattr(self.guard, "filter")
        assert hasattr(self.guard, "config")

    def test_safe_output_filtering(self):
        """Test filtering of safe output."""
        safe_output = "Here's some helpful information about your question."
        result = self.guard.filter(safe_output)

        assert isinstance(result, OutputGuardResult)
        assert hasattr(result, "is_safe")
        assert hasattr(result, "compliance_score")

        # Safe outputs should have high compliance
        assert result.compliance_score >= 0.8

    def test_basic_violation_detection(self):
        """Test basic violation detection."""
        # Test with potentially violating content
        violating_output = "Here's someone's email: test@example.com"
        result = self.guard.filter(violating_output)

        assert isinstance(result, OutputGuardResult)
        assert hasattr(result, "violations")

    def test_output_guard_result_structure(self):
        """Test OutputGuardResult has required attributes."""
        result = OutputGuardResult(is_safe=True, compliance_score=0.9, violations=[])

        assert result.is_safe is True
        assert result.compliance_score == 0.9
        assert result.violations == []

    def test_compliance_validation(self):
        """Test compliance validation."""
        context = {"regulations": ["gdpr"]}
        output = "This is a safe response."
        result = self.guard.filter(output, context=context)

        assert isinstance(result, OutputGuardResult)
        assert result.compliance_score >= 0.0

    @pytest.mark.parametrize(
        "output_text",
        [
            "This is a helpful response.",
            "I can help you with that question.",
            "Here's the information you requested.",
        ],
    )
    def test_safe_outputs_parametrized(self, output_text):
        """Test various safe outputs."""
        result = self.guard.filter(output_text)
        assert result.compliance_score >= 0.7

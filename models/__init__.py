"""
SHIELD Models Package

This package contains all security detection models, model management utilities,
and pre-trained model integrations for the SHIELD framework.

Components:
- ModelManager: Handles model registration, loading, and lifecycle management
- SecurityModels: Specialized threat detection models (injection, toxicity, PII, jailbreak)
- Pre-trained integrations: HuggingFace transformers and custom models
"""

from .model_manager import ModelManager, ModelInfo, model_manager
from .security_models import (
    BaseSecurityModel,
    PromptInjectionDetector,
    ToxicityDetector,
    PIIDetector,
    JailbreakDetector,
    EnsembleSecurityModel,
    ThreatDetectionResult,
    security_ensemble
)

__version__ = "1.0.0"
__author__ = "San Hashim"

# Export main components
__all__ = [
    # Model Management
    'ModelManager',
    'ModelInfo',
    'model_manager',
    
    # Security Models
    'BaseSecurityModel',
    'PromptInjectionDetector',
    'ToxicityDetector',
    'PIIDetector',
    'JailbreakDetector',
    'EnsembleSecurityModel',
    'ThreatDetectionResult',
    'security_ensemble'
]

# Initialize default models on import
try:
    # Download common pre-trained models if not already present
    if not model_manager.list_models():
        print("🔄 Initializing SHIELD security models...")
        model_manager.download_pretrained_models()
        print("✅ Security models initialized successfully")
except Exception as e:
    print(f"⚠️ Warning: Could not initialize pre-trained models: {e}")
    print("   Models can be downloaded manually using model_manager.download_pretrained_models()") 
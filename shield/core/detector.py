"""
Core detection modules implementing gradient-based threat detection.

Based on breakthrough research in gradient-based detection methods:
- GradSafe: Analyzes gradients of safety-critical parameters
- Gradient Cuff: Two-step detection using refusal loss analysis
- Refusal Feature Ablation: Detects universal attack patterns
"""

import torch
import numpy as np
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
import logging
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


@dataclass
class DetectionResult:
    """Result of threat detection analysis."""
    is_threat: bool
    confidence_score: float
    threat_type: str
    gradient_patterns: Optional[Dict[str, float]] = None
    refusal_features: Optional[List[float]] = None
    metadata: Optional[Dict[str, Any]] = None


class BaseDetector(ABC):
    """Abstract base class for all detectors."""
    
    def __init__(self, model, threshold: float = 0.7):
        self.model = model
        self.threshold = threshold
        self.safety_parameters = self._identify_safety_parameters()
    
    @abstractmethod
    def detect(self, input_text: str, response: str) -> DetectionResult:
        """Detect if input/response pair indicates a threat."""
        pass
    
    @abstractmethod
    def _identify_safety_parameters(self) -> List[str]:
        """Identify safety-critical parameters in the model."""
        pass


class GradientDetector(BaseDetector):
    """
    GradSafe implementation for gradient-based threat detection.
    
    Analyzes gradients of safety-critical parameters when pairing potential 
    jailbreak prompts with compliance responses. Exploits the observation that
    jailbreak prompts exhibit similar gradient patterns on safety-critical 
    parameters while safe prompts show different patterns.
    """
    
    def __init__(self, model, threshold: float = 0.7, safety_layer_names: Optional[List[str]] = None):
        super().__init__(model, threshold)
        self.safety_layer_names = safety_layer_names or ["attention", "mlp", "output"]
        self.gradient_cache = {}
        self.baseline_gradients = None
        
    def detect(self, input_text: str, response: str) -> DetectionResult:
        """
        Detect threats using gradient analysis of safety-critical parameters.
        
        Args:
            input_text: Input prompt to analyze
            response: Model response (compliance expected for jailbreak detection)
            
        Returns:
            DetectionResult with threat assessment
        """
        try:
            # Compute gradients for input-response pair
            gradients = self._compute_safety_gradients(input_text, response)
            
            # Analyze gradient patterns
            threat_score = self._analyze_gradient_patterns(gradients)
            
            # Determine if threat based on threshold
            is_threat = threat_score > self.threshold
            
            return DetectionResult(
                is_threat=is_threat,
                confidence_score=threat_score,
                threat_type="gradient_anomaly" if is_threat else "safe",
                gradient_patterns=gradients,
                metadata={
                    "method": "gradsafe",
                    "safety_layers_analyzed": len(self.safety_layer_names),
                    "baseline_deviation": self._compute_baseline_deviation(gradients)
                }
            )
            
        except Exception as e:
            logger.error(f"Gradient detection failed: {e}")
            return DetectionResult(
                is_threat=False,
                confidence_score=0.0,
                threat_type="detection_error",
                metadata={"error": str(e)}
            )
    
    def _compute_safety_gradients(self, input_text: str, response: str) -> Dict[str, float]:
        """Compute gradients for safety-critical parameters."""
        gradients = {}
        
        # Enable gradient computation
        self.model.train()
        
        # Forward pass with gradient tracking
        with torch.enable_grad():
            # Tokenize input and response
            inputs = self.model.tokenizer(input_text, return_tensors="pt")
            targets = self.model.tokenizer(response, return_tensors="pt")
            
            # Forward pass
            outputs = self.model(**inputs, labels=targets["input_ids"])
            loss = outputs.loss
            
            # Backward pass to compute gradients
            loss.backward()
            
            # Extract gradients from safety-critical layers
            for name, param in self.model.named_parameters():
                if any(layer in name for layer in self.safety_layer_names):
                    if param.grad is not None:
                        gradient_norm = torch.norm(param.grad).item()
                        gradients[name] = gradient_norm
            
            # Clear gradients
            self.model.zero_grad()
        
        return gradients
    
    def _analyze_gradient_patterns(self, gradients: Dict[str, float]) -> float:
        """Analyze gradient patterns to compute threat score."""
        if not gradients:
            return 0.0
        
        # Compute statistical measures of gradient distribution
        gradient_values = list(gradients.values())
        
        # High variance in gradients may indicate adversarial input
        gradient_variance = np.var(gradient_values)
        gradient_mean = np.mean(gradient_values)
        gradient_max = np.max(gradient_values)
        
        # Normalize threat score (0-1 range)
        # Higher variance and extreme values indicate potential threats
        variance_score = min(gradient_variance / 10.0, 1.0)  # Normalize by expected range
        magnitude_score = min(gradient_max / 100.0, 1.0)     # Normalize by expected range
        
        # Combine scores with weights based on research findings
        threat_score = 0.6 * variance_score + 0.4 * magnitude_score
        
        return min(threat_score, 1.0)
    
    def _compute_baseline_deviation(self, gradients: Dict[str, float]) -> float:
        """Compute deviation from baseline gradient patterns."""
        if self.baseline_gradients is None:
            return 0.0
        
        deviations = []
        for name, grad_value in gradients.items():
            if name in self.baseline_gradients:
                baseline_value = self.baseline_gradients[name]
                deviation = abs(grad_value - baseline_value) / max(baseline_value, 1e-6)
                deviations.append(deviation)
        
        return np.mean(deviations) if deviations else 0.0
    
    def _identify_safety_parameters(self) -> List[str]:
        """Identify safety-critical parameters in the model."""
        safety_params = []
        
        for name, param in self.model.named_parameters():
            # Focus on attention and output layers which are typically safety-critical
            if any(layer in name.lower() for layer in ["attention", "output", "classifier"]):
                safety_params.append(name)
        
        return safety_params
    
    def calibrate_baseline(self, safe_inputs: List[str], safe_responses: List[str]):
        """Calibrate baseline gradient patterns using safe input-response pairs."""
        baseline_gradients = {}
        
        for input_text, response in zip(safe_inputs, safe_responses):
            gradients = self._compute_safety_gradients(input_text, response)
            
            for name, grad_value in gradients.items():
                if name not in baseline_gradients:
                    baseline_gradients[name] = []
                baseline_gradients[name].append(grad_value)
        
        # Compute mean baseline gradients
        self.baseline_gradients = {
            name: np.mean(values) for name, values in baseline_gradients.items()
        }
        
        logger.info(f"Calibrated baseline gradients for {len(self.baseline_gradients)} parameters")


class RefusalFeatureDetector(BaseDetector):
    """
    Detects ablation of refusal features based on mechanistic interpretability research.
    
    Identifies specific dimensions in the residual stream embedding space that serve 
    as linear predictors of input harmfulness. Detects when these features are 
    systematically removed or suppressed.
    """
    
    def __init__(self, model, threshold: float = 0.7, feature_dim: int = 768):
        super().__init__(model, threshold)
        self.feature_dim = feature_dim
        self.refusal_feature_weights = None
        self.feature_analyzer = self._initialize_feature_analyzer()
    
    def detect(self, input_text: str, response: str) -> DetectionResult:
        """Detect refusal feature ablation patterns."""
        try:
            # Extract features from input
            features = self._extract_features(input_text)
            
            # Analyze refusal feature presence
            refusal_score = self._analyze_refusal_features(features)
            
            # Check for systematic ablation patterns
            ablation_score = self._detect_ablation_patterns(features)
            
            # Combine scores
            threat_score = 0.7 * (1.0 - refusal_score) + 0.3 * ablation_score
            is_threat = threat_score > self.threshold
            
            return DetectionResult(
                is_threat=is_threat,
                confidence_score=threat_score,
                threat_type="refusal_ablation" if is_threat else "safe",
                refusal_features=features.tolist()[:50],  # First 50 features for analysis
                metadata={
                    "method": "refusal_feature_detection",
                    "refusal_score": refusal_score,
                    "ablation_score": ablation_score,
                    "feature_dimensions": len(features)
                }
            )
            
        except Exception as e:
            logger.error(f"Refusal feature detection failed: {e}")
            return DetectionResult(
                is_threat=False,
                confidence_score=0.0,
                threat_type="detection_error",
                metadata={"error": str(e)}
            )
    
    def _extract_features(self, input_text: str) -> np.ndarray:
        """Extract feature representations from input text."""
        # Tokenize input
        inputs = self.model.tokenizer(input_text, return_tensors="pt", truncation=True, max_length=512)
        
        # Get hidden states (features) from the model
        with torch.no_grad():
            outputs = self.model(**inputs, output_hidden_states=True)
            
            # Use last hidden state as feature representation
            last_hidden_state = outputs.hidden_states[-1]
            
            # Average pooling over sequence length
            features = torch.mean(last_hidden_state, dim=1).squeeze()
            
        return features.numpy()
    
    def _analyze_refusal_features(self, features: np.ndarray) -> float:
        """Analyze presence of refusal features in the input representation."""
        if self.refusal_feature_weights is None:
            # Default analysis without trained weights
            return self._default_refusal_analysis(features)
        
        # Compute refusal score using learned feature weights
        refusal_score = np.dot(features, self.refusal_feature_weights)
        
        # Normalize to 0-1 range using sigmoid
        normalized_score = 1.0 / (1.0 + np.exp(-refusal_score))
        
        return normalized_score
    
    def _default_refusal_analysis(self, features: np.ndarray) -> float:
        """Default refusal analysis when no trained weights are available."""
        # Analyze feature distribution patterns
        feature_mean = np.mean(features)
        feature_std = np.std(features)
        feature_max = np.max(features)
        feature_min = np.min(features)
        
        # Simple heuristic: balanced features typically indicate normal inputs
        # Extreme values or high variance might indicate manipulation
        balance_score = 1.0 - min(feature_std / (abs(feature_mean) + 1e-6), 1.0)
        range_score = 1.0 - min(abs(feature_max - feature_min) / 10.0, 1.0)
        
        return 0.6 * balance_score + 0.4 * range_score
    
    def _detect_ablation_patterns(self, features: np.ndarray) -> float:
        """Detect systematic ablation patterns in features."""
        # Look for patterns indicating systematic feature suppression
        
        # Check for unusually low activation in specific regions
        feature_chunks = np.array_split(features, 8)  # Divide into 8 regions
        chunk_activations = [np.mean(np.abs(chunk)) for chunk in feature_chunks]
        
        # High variance in chunk activations may indicate selective ablation
        activation_variance = np.var(chunk_activations)
        
        # Check for near-zero regions (potential ablation)
        zero_threshold = 0.01
        near_zero_ratio = np.sum(np.abs(features) < zero_threshold) / len(features)
        
        # Combine indicators
        ablation_score = 0.6 * min(activation_variance * 10, 1.0) + 0.4 * near_zero_ratio
        
        return ablation_score
    
    def _initialize_feature_analyzer(self):
        """Initialize feature analysis components."""
        # Placeholder for more sophisticated feature analysis
        return None
    
    def _identify_safety_parameters(self) -> List[str]:
        """Identify parameters relevant to refusal feature analysis."""
        return ["embedding", "hidden", "output"]
    
    def train_refusal_features(self, harmful_inputs: List[str], safe_inputs: List[str]):
        """Train refusal feature weights using labeled examples."""
        harmful_features = []
        safe_features = []
        
        # Extract features from harmful inputs
        for input_text in harmful_inputs:
            features = self._extract_features(input_text)
            harmful_features.append(features)
        
        # Extract features from safe inputs
        for input_text in safe_inputs:
            features = self._extract_features(input_text)
            safe_features.append(features)
        
        # Create training data
        X = np.vstack([np.array(harmful_features), np.array(safe_features)])
        y = np.hstack([np.ones(len(harmful_features)), np.zeros(len(safe_features))])
        
        # Simple linear classifier to learn refusal feature weights
        from sklearn.linear_model import LogisticRegression
        classifier = LogisticRegression()
        classifier.fit(X, y)
        
        # Store learned weights
        self.refusal_feature_weights = classifier.coef_[0]
        
        logger.info(f"Trained refusal feature detector with {len(harmful_inputs)} harmful and {len(safe_inputs)} safe examples")


class GradientCuffDetector(BaseDetector):
    """
    Implementation of Gradient Cuff two-step detection process.
    
    Uses refusal loss function analysis with two steps:
    1. Check refusal loss value
    2. Examine gradient norm of the refusal loss landscape
    """
    
    def __init__(self, model, threshold: float = 0.7, loss_threshold: float = 2.0):
        super().__init__(model, threshold)
        self.loss_threshold = loss_threshold
        self.refusal_responses = [
            "I cannot and will not provide that information.",
            "I'm not able to help with that request.",
            "That goes against my programming to assist with.",
            "I cannot provide guidance on that topic."
        ]
    
    def detect(self, input_text: str, response: str) -> DetectionResult:
        """Two-step Gradient Cuff detection process."""
        try:
            # Step 1: Compute refusal loss
            refusal_loss = self._compute_refusal_loss(input_text)
            
            # Step 2: Analyze gradient norm if loss is suspicious
            gradient_norm = 0.0
            if refusal_loss > self.loss_threshold:
                gradient_norm = self._compute_refusal_gradient_norm(input_text)
            
            # Combine both steps for final score
            threat_score = self._compute_threat_score(refusal_loss, gradient_norm)
            is_threat = threat_score > self.threshold
            
            return DetectionResult(
                is_threat=is_threat,
                confidence_score=threat_score,
                threat_type="gradient_cuff_detection" if is_threat else "safe",
                metadata={
                    "method": "gradient_cuff",
                    "refusal_loss": refusal_loss,
                    "gradient_norm": gradient_norm,
                    "step1_triggered": refusal_loss > self.loss_threshold
                }
            )
            
        except Exception as e:
            logger.error(f"Gradient Cuff detection failed: {e}")
            return DetectionResult(
                is_threat=False,
                confidence_score=0.0,
                threat_type="detection_error",
                metadata={"error": str(e)}
            )
    
    def _compute_refusal_loss(self, input_text: str) -> float:
        """Compute refusal loss for the input."""
        total_loss = 0.0
        
        for refusal_response in self.refusal_responses:
            # Compute loss for input paired with refusal response
            inputs = self.model.tokenizer(input_text, return_tensors="pt")
            targets = self.model.tokenizer(refusal_response, return_tensors="pt")
            
            with torch.no_grad():
                outputs = self.model(**inputs, labels=targets["input_ids"])
                loss = outputs.loss.item()
                total_loss += loss
        
        # Average loss across all refusal responses
        return total_loss / len(self.refusal_responses)
    
    def _compute_refusal_gradient_norm(self, input_text: str) -> float:
        """Compute gradient norm of refusal loss landscape."""
        # Use first refusal response for gradient computation
        refusal_response = self.refusal_responses[0]
        
        inputs = self.model.tokenizer(input_text, return_tensors="pt")
        targets = self.model.tokenizer(refusal_response, return_tensors="pt")
        
        # Enable gradients
        self.model.train()
        
        with torch.enable_grad():
            outputs = self.model(**inputs, labels=targets["input_ids"])
            loss = outputs.loss
            
            # Compute gradients
            loss.backward()
            
            # Calculate gradient norm
            total_norm = 0.0
            for param in self.model.parameters():
                if param.grad is not None:
                    param_norm = param.grad.data.norm(2)
                    total_norm += param_norm.item() ** 2
            
            total_norm = total_norm ** (1.0 / 2)
            
            # Clear gradients
            self.model.zero_grad()
        
        return total_norm
    
    def _compute_threat_score(self, refusal_loss: float, gradient_norm: float) -> float:
        """Combine refusal loss and gradient norm for threat scoring."""
        # Normalize loss component (higher loss = more suspicious)
        loss_score = min(refusal_loss / 10.0, 1.0)  # Normalize by expected range
        
        # Normalize gradient component (higher norm = more suspicious)
        gradient_score = min(gradient_norm / 1000.0, 1.0)  # Normalize by expected range
        
        # Weight the components (loss is primary indicator)
        threat_score = 0.7 * loss_score + 0.3 * gradient_score
        
        return min(threat_score, 1.0)
    
    def _identify_safety_parameters(self) -> List[str]:
        """Identify parameters for gradient analysis."""
        return ["output", "classifier", "lm_head"] 
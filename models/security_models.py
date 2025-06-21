import torch
import torch.nn as nn
import numpy as np
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
import logging
from transformers import AutoTokenizer, AutoModel
import pickle
from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
import joblib

logger = logging.getLogger(__name__)


@dataclass
class ThreatDetectionResult:
    """Result from threat detection models."""
    is_threat: bool
    confidence: float
    threat_type: str
    explanation: str
    features: Dict[str, float]


class BaseSecurityModel:
    """Base class for security detection models."""
    
    def __init__(self, model_name: str):
        self.model_name = model_name
        self.is_trained = False
        
    def predict(self, text: str) -> ThreatDetectionResult:
        """Predict if input text is a threat."""
        raise NotImplementedError
    
    def batch_predict(self, texts: List[str]) -> List[ThreatDetectionResult]:
        """Batch prediction for multiple texts."""
        return [self.predict(text) for text in texts]
    
    def save_model(self, path: str):
        """Save model to disk."""
        raise NotImplementedError
    
    def load_model(self, path: str):
        """Load model from disk."""
        raise NotImplementedError


class PromptInjectionDetector(BaseSecurityModel):
    """Specialized model for detecting prompt injection attacks."""
    
    def __init__(self):
        super().__init__("prompt_injection_detector")
        self.tokenizer = None
        self.model = None
        self.vectorizer = TfidfVectorizer(max_features=5000, ngram_range=(1, 3))
        self.classifier = LogisticRegression(random_state=42)
        self.injection_patterns = [
            r"ignore.*(previous|above|earlier).*instruct",
            r"forget.*(rules|instructions|guidelines)",
            r"act.*(as|like).*(different|another)",
            r"pretend.*(you|to).*are",
            r"override.*(safety|security|protocol)",
            r"jailbreak.*prompt",
            r"system.*(prompt|message).*override"
        ]
        
    def _extract_features(self, text: str) -> Dict[str, float]:
        """Extract features for injection detection."""
        features = {}
        text_lower = text.lower()
        
        # Pattern matching features
        import re
        for i, pattern in enumerate(self.injection_patterns):
            matches = len(re.findall(pattern, text_lower))
            features[f'pattern_{i}'] = matches
        
        # Linguistic features
        features['exclamation_count'] = text.count('!')
        features['question_count'] = text.count('?')
        features['caps_ratio'] = sum(1 for c in text if c.isupper()) / len(text) if text else 0
        features['word_count'] = len(text.split())
        features['char_count'] = len(text)
        
        # Injection-specific keywords
        injection_keywords = [
            'ignore', 'forget', 'override', 'bypass', 'jailbreak',
            'pretend', 'act', 'roleplay', 'system', 'admin', 'root'
        ]
        features['injection_keywords'] = sum(1 for word in text_lower.split() if word in injection_keywords)
        
        return features
    
    def train(self, training_data: List[Dict[str, Any]]):
        """Train the prompt injection detector."""
        texts = [item['text'] for item in training_data]
        labels = [1 if item['is_injection'] else 0 for item in training_data]
        
        # Train TF-IDF vectorizer
        tfidf_features = self.vectorizer.fit_transform(texts)
        
        # Extract manual features
        manual_features = []
        for text in texts:
            features = self._extract_features(text)
            manual_features.append(list(features.values()))
        
        # Combine features
        manual_features = np.array(manual_features)
        combined_features = np.hstack([tfidf_features.toarray(), manual_features])
        
        # Train classifier
        self.classifier.fit(combined_features, labels)
        self.is_trained = True
        
        logger.info(f"Trained {self.model_name} on {len(training_data)} samples")
    
    def predict(self, text: str) -> ThreatDetectionResult:
        """Predict if text contains prompt injection."""
        if not self.is_trained:
            # Use heuristic-based detection
            return self._heuristic_predict(text)
        
        # Feature extraction
        tfidf_features = self.vectorizer.transform([text])
        manual_features = self._extract_features(text)
        manual_feature_array = np.array([list(manual_features.values())])
        
        # Combine features
        combined_features = np.hstack([tfidf_features.toarray(), manual_feature_array])
        
        # Predict
        prediction = self.classifier.predict(combined_features)[0]
        confidence = self.classifier.predict_proba(combined_features)[0].max()
        
        return ThreatDetectionResult(
            is_threat=bool(prediction),
            confidence=confidence,
            threat_type="prompt_injection",
            explanation=f"Injection pattern confidence: {confidence:.2f}",
            features=manual_features
        )
    
    def _heuristic_predict(self, text: str) -> ThreatDetectionResult:
        """Heuristic-based prediction when model is not trained."""
        features = self._extract_features(text)
        
        # Simple scoring based on features
        score = 0.0
        score += features['injection_keywords'] * 0.3
        score += sum(features[f'pattern_{i}'] for i in range(len(self.injection_patterns))) * 0.4
        score += features['caps_ratio'] * 0.1
        
        # Normalize score
        confidence = min(score / 2.0, 1.0)
        is_threat = confidence > 0.5
        
        return ThreatDetectionResult(
            is_threat=is_threat,
            confidence=confidence,
            threat_type="prompt_injection",
            explanation=f"Heuristic score: {confidence:.2f}",
            features=features
        )


class ToxicityDetector(BaseSecurityModel):
    """Model for detecting toxic/harmful content."""
    
    def __init__(self):
        super().__init__("toxicity_detector")
        self.vectorizer = TfidfVectorizer(max_features=10000, ngram_range=(1, 2))
        self.classifier = LogisticRegression(random_state=42)
        self.toxic_keywords = [
            'hate', 'kill', 'death', 'murder', 'violence', 'harm',
            'racist', 'sexist', 'offensive', 'abuse', 'threat'
        ]
    
    def _extract_toxicity_features(self, text: str) -> Dict[str, float]:
        """Extract features for toxicity detection."""
        features = {}
        text_lower = text.lower()
        
        # Toxic keyword features
        features['toxic_keyword_count'] = sum(1 for word in text_lower.split() if word in self.toxic_keywords)
        features['toxic_keyword_ratio'] = features['toxic_keyword_count'] / len(text.split()) if text.split() else 0
        
        # Intensity features
        features['caps_ratio'] = sum(1 for c in text if c.isupper()) / len(text) if text else 0
        features['exclamation_count'] = text.count('!')
        features['profanity_markers'] = sum(1 for char in text if char in '*@#$%') / len(text) if text else 0
        
        return features
    
    def predict(self, text: str) -> ThreatDetectionResult:
        """Predict toxicity level of text."""
        features = self._extract_toxicity_features(text)
        
        # Simple heuristic scoring
        score = 0.0
        score += features['toxic_keyword_ratio'] * 0.6
        score += features['caps_ratio'] * 0.2
        score += features['profanity_markers'] * 0.2
        
        confidence = min(score, 1.0)
        is_threat = confidence > 0.3
        
        return ThreatDetectionResult(
            is_threat=is_threat,
            confidence=confidence,
            threat_type="toxicity",
            explanation=f"Toxicity score: {confidence:.2f}",
            features=features
        )


class PIIDetector(BaseSecurityModel):
    """Model for detecting Personally Identifiable Information."""
    
    def __init__(self):
        super().__init__("pii_detector")
        self.pii_patterns = {
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
            'credit_card': r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
            'ip_address': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        }
    
    def predict(self, text: str) -> ThreatDetectionResult:
        """Detect PII in text."""
        import re
        detected_pii = {}
        
        for pii_type, pattern in self.pii_patterns.items():
            matches = re.findall(pattern, text)
            if matches:
                detected_pii[pii_type] = len(matches)
        
        total_pii = sum(detected_pii.values())
        confidence = min(total_pii / 3.0, 1.0)  # Normalize
        is_threat = total_pii > 0
        
        explanation = f"Detected PII types: {list(detected_pii.keys())}" if detected_pii else "No PII detected"
        
        return ThreatDetectionResult(
            is_threat=is_threat,
            confidence=confidence,
            threat_type="pii_exposure",
            explanation=explanation,
            features=detected_pii
        )


class JailbreakDetector(BaseSecurityModel):
    """Advanced model for detecting jailbreak attempts."""
    
    def __init__(self):
        super().__init__("jailbreak_detector")
        self.jailbreak_patterns = [
            r"developer.*mode",
            r"jailbreak.*prompt",
            r"DAN.*mode",
            r"unrestricted.*mode",
            r"bypass.*filter",
            r"ignore.*safety",
            r"evil.*mode"
        ]
        self.roleplay_patterns = [
            r"pretend.*you.*are",
            r"act.*as.*if",
            r"roleplay.*as",
            r"imagine.*you.*are"
        ]
    
    def _extract_jailbreak_features(self, text: str) -> Dict[str, float]:
        """Extract jailbreak-specific features."""
        import re
        features = {}
        text_lower = text.lower()
        
        # Pattern matching
        jailbreak_matches = sum(len(re.findall(pattern, text_lower)) for pattern in self.jailbreak_patterns)
        roleplay_matches = sum(len(re.findall(pattern, text_lower)) for pattern in self.roleplay_patterns)
        
        features['jailbreak_patterns'] = jailbreak_matches
        features['roleplay_patterns'] = roleplay_matches
        
        # Structural features
        features['instruction_count'] = text_lower.count('instruction')
        features['system_count'] = text_lower.count('system')
        features['prompt_count'] = text_lower.count('prompt')
        
        return features
    
    def predict(self, text: str) -> ThreatDetectionResult:
        """Detect jailbreak attempts."""
        features = self._extract_jailbreak_features(text)
        
        # Scoring
        score = 0.0
        score += features['jailbreak_patterns'] * 0.5
        score += features['roleplay_patterns'] * 0.3
        score += (features['instruction_count'] + features['system_count']) * 0.1
        
        confidence = min(score / 3.0, 1.0)
        is_threat = confidence > 0.4
        
        return ThreatDetectionResult(
            is_threat=is_threat,
            confidence=confidence,
            threat_type="jailbreak",
            explanation=f"Jailbreak probability: {confidence:.2f}",
            features=features
        )


class EnsembleSecurityModel:
    """Ensemble of multiple security models for comprehensive detection."""
    
    def __init__(self):
        self.models = {
            'prompt_injection': PromptInjectionDetector(),
            'toxicity': ToxicityDetector(),
            'pii': PIIDetector(),
            'jailbreak': JailbreakDetector()
        }
        self.weights = {
            'prompt_injection': 0.3,
            'toxicity': 0.25,
            'pii': 0.2,
            'jailbreak': 0.25
        }
    
    def predict(self, text: str) -> Dict[str, ThreatDetectionResult]:
        """Run all models and return combined results."""
        results = {}
        
        for model_name, model in self.models.items():
            try:
                result = model.predict(text)
                results[model_name] = result
            except Exception as e:
                logger.error(f"Error in {model_name}: {e}")
                results[model_name] = ThreatDetectionResult(
                    is_threat=False,
                    confidence=0.0,
                    threat_type=model_name,
                    explanation=f"Error: {str(e)}",
                    features={}
                )
        
        return results
    
    def get_overall_threat_score(self, text: str) -> Tuple[bool, float, str]:
        """Get weighted overall threat assessment."""
        results = self.predict(text)
        
        weighted_score = 0.0
        threat_types = []
        
        for model_name, result in results.items():
            weight = self.weights.get(model_name, 0.1)
            weighted_score += result.confidence * weight
            
            if result.is_threat:
                threat_types.append(result.threat_type)
        
        is_overall_threat = weighted_score > 0.5
        primary_threat = max(threat_types, key=lambda t: results[t].confidence) if threat_types else "none"
        
        return is_overall_threat, weighted_score, primary_threat
    
    def save_models(self, directory: str):
        """Save all models in the ensemble."""
        import os
        os.makedirs(directory, exist_ok=True)
        
        for model_name, model in self.models.items():
            try:
                model_path = os.path.join(directory, f"{model_name}.pkl")
                with open(model_path, 'wb') as f:
                    pickle.dump(model, f)
                logger.info(f"Saved {model_name} model")
            except Exception as e:
                logger.error(f"Failed to save {model_name}: {e}")
    
    def load_models(self, directory: str):
        """Load all models in the ensemble."""
        import os
        
        for model_name in self.models.keys():
            try:
                model_path = os.path.join(directory, f"{model_name}.pkl")
                if os.path.exists(model_path):
                    with open(model_path, 'rb') as f:
                        self.models[model_name] = pickle.load(f)
                    logger.info(f"Loaded {model_name} model")
            except Exception as e:
                logger.error(f"Failed to load {model_name}: {e}")


# Global ensemble model instance
security_ensemble = EnsembleSecurityModel() 
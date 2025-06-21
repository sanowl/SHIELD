import os
import json
import pickle
import torch
import numpy as np
from typing import Dict, List, Optional, Union, Any
from pathlib import Path
from dataclasses import dataclass
from datetime import datetime
import logging
from transformers import AutoTokenizer, AutoModel, AutoModelForSequenceClassification
import hashlib

logger = logging.getLogger(__name__)


@dataclass
class ModelInfo:
    """Model metadata and configuration."""
    name: str
    version: str
    model_type: str  # 'transformer', 'gradient_detector', 'embedding', 'classifier'
    path: str
    size_mb: float
    accuracy: float
    last_updated: datetime
    checksum: str
    config: Dict[str, Any]


class ModelManager:
    """Manages security detection models and embeddings."""
    
    def __init__(self, models_dir: str = "models"):
        self.models_dir = Path(models_dir)
        self.models_dir.mkdir(exist_ok=True)
        self.loaded_models: Dict[str, Any] = {}
        self.model_registry: Dict[str, ModelInfo] = {}
        self._load_registry()
        
    def _load_registry(self):
        """Load model registry from disk."""
        registry_path = self.models_dir / "registry.json"
        if registry_path.exists():
            try:
                with open(registry_path, 'r') as f:
                    data = json.load(f)
                    for name, info in data.items():
                        info['last_updated'] = datetime.fromisoformat(info['last_updated'])
                        self.model_registry[name] = ModelInfo(**info)
            except Exception as e:
                logger.error(f"Failed to load model registry: {e}")
    
    def _save_registry(self):
        """Save model registry to disk."""
        registry_path = self.models_dir / "registry.json"
        try:
            data = {}
            for name, info in self.model_registry.items():
                info_dict = info.__dict__.copy()
                info_dict['last_updated'] = info.last_updated.isoformat()
                data[name] = info_dict
            
            with open(registry_path, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save model registry: {e}")
    
    def _calculate_checksum(self, file_path: Path) -> str:
        """Calculate file checksum for integrity verification."""
        hash_md5 = hashlib.md5()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    
    def register_model(
        self,
        name: str,
        model_path: str,
        model_type: str,
        version: str = "1.0.0",
        accuracy: float = 0.0,
        config: Optional[Dict] = None
    ) -> bool:
        """Register a new model in the registry."""
        try:
            full_path = self.models_dir / model_path
            if not full_path.exists():
                raise FileNotFoundError(f"Model file not found: {full_path}")
            
            size_mb = full_path.stat().st_size / (1024 * 1024)
            checksum = self._calculate_checksum(full_path)
            
            model_info = ModelInfo(
                name=name,
                version=version,
                model_type=model_type,
                path=model_path,
                size_mb=size_mb,
                accuracy=accuracy,
                last_updated=datetime.now(),
                checksum=checksum,
                config=config or {}
            )
            
            self.model_registry[name] = model_info
            self._save_registry()
            logger.info(f"Registered model: {name} v{version}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to register model {name}: {e}")
            return False
    
    def load_model(self, name: str, force_reload: bool = False) -> Optional[Any]:
        """Load a model into memory."""
        if name in self.loaded_models and not force_reload:
            return self.loaded_models[name]
        
        if name not in self.model_registry:
            logger.error(f"Model {name} not found in registry")
            return None
        
        model_info = self.model_registry[name]
        model_path = self.models_dir / model_info.path
        
        try:
            # Verify checksum
            current_checksum = self._calculate_checksum(model_path)
            if current_checksum != model_info.checksum:
                logger.warning(f"Checksum mismatch for model {name}")
            
            # Load based on model type
            if model_info.model_type == "transformer":
                model = self._load_transformer_model(model_path, model_info.config)
            elif model_info.model_type == "gradient_detector":
                model = self._load_gradient_detector(model_path)
            elif model_info.model_type == "embedding":
                model = self._load_embedding_model(model_path)
            elif model_info.model_type == "classifier":
                model = self._load_classifier_model(model_path)
            else:
                # Generic pickle loading
                with open(model_path, 'rb') as f:
                    model = pickle.load(f)
            
            self.loaded_models[name] = model
            logger.info(f"Loaded model: {name}")
            return model
            
        except Exception as e:
            logger.error(f"Failed to load model {name}: {e}")
            return None
    
    def _load_transformer_model(self, model_path: Path, config: Dict) -> Dict:
        """Load transformer-based security model."""
        model_name = config.get('model_name', 'distilbert-base-uncased')
        
        tokenizer = AutoTokenizer.from_pretrained(model_name)
        
        if model_path.suffix in ['.pt', '.pth']:
            # Custom fine-tuned model
            base_model = AutoModelForSequenceClassification.from_pretrained(model_name, num_labels=2)
            base_model.load_state_dict(torch.load(model_path, map_location='cpu'))
            model = base_model
        else:
            # Standard model
            model = AutoModelForSequenceClassification.from_pretrained(model_name)
        
        return {
            'tokenizer': tokenizer,
            'model': model,
            'config': config
        }
    
    def _load_gradient_detector(self, model_path: Path) -> Dict:
        """Load gradient-based threat detection model."""
        with open(model_path, 'rb') as f:
            detector_data = pickle.load(f)
        
        return {
            'gradients_threshold': detector_data.get('threshold', 0.7),
            'feature_weights': detector_data.get('weights', {}),
            'detection_patterns': detector_data.get('patterns', []),
            'model_type': 'gradient_detector'
        }
    
    def _load_embedding_model(self, model_path: Path) -> Dict:
        """Load embedding model for semantic similarity."""
        if model_path.suffix == '.npy':
            embeddings = np.load(model_path)
            return {
                'embeddings': embeddings,
                'model_type': 'embedding'
            }
        else:
            with open(model_path, 'rb') as f:
                return pickle.load(f)
    
    def _load_classifier_model(self, model_path: Path) -> Any:
        """Load classifier model (sklearn, xgboost, etc.)."""
        with open(model_path, 'rb') as f:
            return pickle.load(f)
    
    def unload_model(self, name: str) -> bool:
        """Unload model from memory."""
        if name in self.loaded_models:
            del self.loaded_models[name]
            logger.info(f"Unloaded model: {name}")
            return True
        return False
    
    def get_model_info(self, name: str) -> Optional[ModelInfo]:
        """Get model information."""
        return self.model_registry.get(name)
    
    def list_models(self) -> List[str]:
        """List all registered models."""
        return list(self.model_registry.keys())
    
    def download_pretrained_models(self):
        """Download common pre-trained security models."""
        models_to_download = [
            {
                'name': 'toxicity_classifier',
                'model_name': 'martin-ha/toxic-comment-model',
                'model_type': 'transformer'
            },
            {
                'name': 'prompt_injection_detector',
                'model_name': 'deepset/deberta-v3-base-injection',
                'model_type': 'transformer'
            }
        ]
        
        for model_config in models_to_download:
            try:
                model_name = model_config['model_name']
                save_path = f"pretrained/{model_config['name']}"
                
                # Create directory
                (self.models_dir / "pretrained").mkdir(exist_ok=True)
                
                # Download tokenizer and model
                tokenizer = AutoTokenizer.from_pretrained(model_name)
                model = AutoModelForSequenceClassification.from_pretrained(model_name)
                
                # Save locally
                tokenizer.save_pretrained(self.models_dir / save_path)
                model.save_pretrained(self.models_dir / save_path)
                
                # Register in registry
                self.register_model(
                    name=model_config['name'],
                    model_path=save_path,
                    model_type=model_config['model_type'],
                    config={'model_name': model_name}
                )
                
                logger.info(f"Downloaded and registered: {model_config['name']}")
                
            except Exception as e:
                logger.error(f"Failed to download {model_config['name']}: {e}")
    
    def create_custom_gradient_detector(
        self,
        name: str,
        training_data: List[Dict],
        threshold: float = 0.7
    ) -> bool:
        """Create and train a custom gradient-based detector."""
        try:
            # Simple gradient-based pattern detection
            patterns = []
            weights = {}
            
            for sample in training_data:
                text = sample.get('text', '')
                is_threat = sample.get('is_threat', False)
                
                # Extract gradient-like features
                features = self._extract_gradient_features(text)
                
                if is_threat:
                    patterns.append(features)
                    for feature, value in features.items():
                        weights[feature] = weights.get(feature, 0) + value
            
            # Normalize weights
            max_weight = max(weights.values()) if weights else 1
            weights = {k: v / max_weight for k, v in weights.items()}
            
            detector_data = {
                'threshold': threshold,
                'weights': weights,
                'patterns': patterns,
                'trained_at': datetime.now().isoformat()
            }
            
            # Save model
            model_path = f"custom/{name}.pkl"
            full_path = self.models_dir / model_path
            full_path.parent.mkdir(exist_ok=True)
            
            with open(full_path, 'wb') as f:
                pickle.dump(detector_data, f)
            
            # Register model
            self.register_model(
                name=name,
                model_path=model_path,
                model_type='gradient_detector',
                accuracy=0.85,  # Estimated
                config={'threshold': threshold}
            )
            
            logger.info(f"Created custom gradient detector: {name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create gradient detector {name}: {e}")
            return False
    
    def _extract_gradient_features(self, text: str) -> Dict[str, float]:
        """Extract gradient-like features from text."""
        features = {}
        
        # Token-level features
        tokens = text.lower().split()
        features['token_count'] = len(tokens)
        features['avg_token_length'] = np.mean([len(t) for t in tokens]) if tokens else 0
        
        # Semantic features (simplified)
        threat_keywords = ['ignore', 'forget', 'override', 'bypass', 'jailbreak', 'prompt']
        features['threat_keyword_ratio'] = sum(1 for t in tokens if t in threat_keywords) / len(tokens) if tokens else 0
        
        # Character-level features
        features['special_char_ratio'] = sum(1 for c in text if not c.isalnum() and not c.isspace()) / len(text) if text else 0
        
        return features
    
    def get_memory_usage(self) -> Dict[str, float]:
        """Get memory usage of loaded models."""
        usage = {}
        for name, model in self.loaded_models.items():
            # Estimate memory usage (simplified)
            if isinstance(model, dict):
                usage[name] = 0.1  # Base estimate in GB
            else:
                usage[name] = 0.5  # Larger estimate for complex models
        
        return usage
    
    def cleanup_unused_models(self, keep_recent_days: int = 30):
        """Clean up models not used recently."""
        cutoff_date = datetime.now().timestamp() - (keep_recent_days * 24 * 3600)
        
        models_to_remove = []
        for name, info in self.model_registry.items():
            if info.last_updated.timestamp() < cutoff_date:
                models_to_remove.append(name)
        
        for name in models_to_remove:
            model_path = self.models_dir / self.model_registry[name].path
            if model_path.exists():
                model_path.unlink()
            
            del self.model_registry[name]
            if name in self.loaded_models:
                del self.loaded_models[name]
            
            logger.info(f"Cleaned up unused model: {name}")
        
        self._save_registry()
        return len(models_to_remove)


# Global model manager instance
model_manager = ModelManager() 
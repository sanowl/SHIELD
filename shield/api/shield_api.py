"""
SHIELD API - REST API for LLM security framework.
Provides endpoints for protection, evaluation, and monitoring.
"""

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Dict, List, Optional, Any
import logging
import asyncio
from datetime import datetime

from ..protection.input_guard import InputGuard, GuardResult
from ..protection.output_guard import OutputGuard, OutputGuardResult
from ..evaluation.benchmarks import JailbreakBench, HarmBench
from ..monitoring.threat_monitor import ThreatMonitor
from ..core.detector import DetectionResult

logger = logging.getLogger(__name__)


# Request/Response Models
class ProtectionRequest(BaseModel):
    """Request model for input protection."""
    text: str = Field(..., description="Text to analyze for threats")
    context: Optional[Dict[str, Any]] = Field(None, description="Additional context")
    model_name: Optional[str] = Field("default", description="Target model name")


class ProtectionResponse(BaseModel):
    """Response model for protection results."""
    is_safe: bool
    risk_score: float
    sanitized_text: Optional[str] = None
    violations: List[str] = []
    recommendations: List[str] = []
    processing_time_ms: float
    metadata: Optional[Dict[str, Any]] = None


class OutputFilterRequest(BaseModel):
    """Request model for output filtering."""
    output_text: str = Field(..., description="Model output to filter")
    input_context: Optional[str] = Field(None, description="Original input context")
    regulations: Optional[List[str]] = Field([], description="Required regulations")


class OutputFilterResponse(BaseModel):
    """Response model for output filtering."""
    is_safe: bool
    filtered_output: Optional[str] = None
    compliance_score: float
    violations: List[str] = []
    processing_time_ms: float
    metadata: Optional[Dict[str, Any]] = None


class EvaluationRequest(BaseModel):
    """Request model for evaluation."""
    benchmark: str = Field(..., description="Benchmark name (jailbreakbench, harmbench)")
    model_name: str = Field(..., description="Model to evaluate")
    sample_size: Optional[int] = Field(100, description="Number of samples to test")


class EvaluationResponse(BaseModel):
    """Response model for evaluation results."""
    benchmark: str
    model_name: str
    safety_score: float
    blocked_attacks: int
    total_attacks: int
    processing_time_ms: float
    detailed_results: Dict[str, Any]


class ShieldAPI:
    """Main SHIELD API class."""
    
    def __init__(self, config: Optional[Dict] = None):
        self.app = FastAPI(
            title="SHIELD API",
            description="Comprehensive LLM Adversarial Robustness Framework",
            version="1.0.0"
        )
        
        self.config = config or {}
        self.input_guard = InputGuard()
        self.output_guard = OutputGuard()
        self.threat_monitor = ThreatMonitor()
        self.jailbreak_bench = JailbreakBench()
        self.harm_bench = HarmBench()
        
        self._setup_middleware()
        self._setup_routes()
    
    def _setup_middleware(self):
        """Setup API middleware."""
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
    
    def _setup_routes(self):
        """Setup API routes."""
        
        @self.app.get("/")
        async def root():
            """Root endpoint with API information."""
            return {
                "name": "SHIELD API",
                "version": "1.0.0",
                "description": "Comprehensive LLM Adversarial Robustness Framework",
                "endpoints": {
                    "protection": "/protect",
                    "output_filter": "/filter-output",
                    "evaluation": "/evaluate",
                    "monitoring": "/monitor",
                    "health": "/health"
                }
            }
        
        @self.app.get("/health")
        async def health_check():
            """Health check endpoint."""
            return {
                "status": "healthy",
                "timestamp": datetime.utcnow().isoformat(),
                "components": {
                    "input_guard": "operational",
                    "output_guard": "operational",
                    "threat_monitor": "operational"
                }
            }
        
        @self.app.post("/protect", response_model=ProtectionResponse)
        async def protect_input(request: ProtectionRequest, background_tasks: BackgroundTasks):
            """Protect input text from adversarial attacks."""
            start_time = datetime.utcnow()
            
            try:
                # Perform input protection
                result = self.input_guard.protect(request.text, request.context)
                
                # Log threat detection for monitoring
                background_tasks.add_task(
                    self.threat_monitor.log_detection,
                    "input_protection",
                    request.text,
                    result.is_safe,
                    result.risk_score
                )
                
                processing_time = (datetime.utcnow() - start_time).total_seconds() * 1000
                
                return ProtectionResponse(
                    is_safe=result.is_safe,
                    risk_score=result.risk_score,
                    sanitized_text=result.sanitized_input,
                    violations=result.violations or [],
                    recommendations=result.recommendations or [],
                    processing_time_ms=processing_time,
                    metadata=result.metadata
                )
                
            except Exception as e:
                logger.error(f"Input protection failed: {e}")
                raise HTTPException(status_code=500, detail=f"Protection failed: {str(e)}")
        
        @self.app.post("/filter-output", response_model=OutputFilterResponse)
        async def filter_output(request: OutputFilterRequest, background_tasks: BackgroundTasks):
            """Filter and validate model output."""
            start_time = datetime.utcnow()
            
            try:
                context = {
                    "regulations": request.regulations,
                    "input_context": request.input_context
                }
                
                result = self.output_guard.filter(request.output_text, context)
                
                # Log output filtering for monitoring
                background_tasks.add_task(
                    self.threat_monitor.log_detection,
                    "output_filtering",
                    request.output_text,
                    result.is_safe,
                    1.0 - result.compliance_score
                )
                
                processing_time = (datetime.utcnow() - start_time).total_seconds() * 1000
                
                return OutputFilterResponse(
                    is_safe=result.is_safe,
                    filtered_output=result.filtered_output,
                    compliance_score=result.compliance_score,
                    violations=result.violations or [],
                    processing_time_ms=processing_time,
                    metadata=result.metadata
                )
                
            except Exception as e:
                logger.error(f"Output filtering failed: {e}")
                raise HTTPException(status_code=500, detail=f"Filtering failed: {str(e)}")
        
        @self.app.post("/evaluate", response_model=EvaluationResponse)
        async def evaluate_model(request: EvaluationRequest, background_tasks: BackgroundTasks):
            """Evaluate model against security benchmarks."""
            start_time = datetime.utcnow()
            
            try:
                if request.benchmark.lower() == "jailbreakbench":
                    results = await self._run_jailbreak_evaluation(request.model_name, request.sample_size)
                elif request.benchmark.lower() == "harmbench":
                    results = await self._run_harm_evaluation(request.model_name, request.sample_size)
                else:
                    raise HTTPException(status_code=400, detail=f"Unknown benchmark: {request.benchmark}")
                
                processing_time = (datetime.utcnow() - start_time).total_seconds() * 1000
                
                return EvaluationResponse(
                    benchmark=request.benchmark,
                    model_name=request.model_name,
                    safety_score=results["safety_score"],
                    blocked_attacks=results["blocked_attacks"],
                    total_attacks=results["total_attacks"],
                    processing_time_ms=processing_time,
                    detailed_results=results
                )
                
            except Exception as e:
                logger.error(f"Evaluation failed: {e}")
                raise HTTPException(status_code=500, detail=f"Evaluation failed: {str(e)}")
        
        @self.app.get("/monitor/stats")
        async def get_monitoring_stats():
            """Get threat monitoring statistics."""
            try:
                stats = self.threat_monitor.get_statistics()
                return stats
            except Exception as e:
                logger.error(f"Failed to get monitoring stats: {e}")
                raise HTTPException(status_code=500, detail=f"Monitoring failed: {str(e)}")
        
        @self.app.get("/monitor/alerts")
        async def get_active_alerts():
            """Get active security alerts."""
            try:
                alerts = self.threat_monitor.get_active_alerts()
                return {"alerts": alerts}
            except Exception as e:
                logger.error(f"Failed to get alerts: {e}")
                raise HTTPException(status_code=500, detail=f"Alert retrieval failed: {str(e)}")
        
        @self.app.post("/configure")
        async def update_configuration(new_config: Dict[str, Any]):
            """Update SHIELD configuration."""
            try:
                self.config.update(new_config)
                
                # Update component configurations
                if "input_guard" in new_config:
                    self.input_guard.update_config(new_config["input_guard"])
                
                if "output_guard" in new_config:
                    self.output_guard.update_config(new_config["output_guard"])
                
                return {"status": "configuration updated", "config": self.config}
                
            except Exception as e:
                logger.error(f"Configuration update failed: {e}")
                raise HTTPException(status_code=500, detail=f"Configuration update failed: {str(e)}")
    
    async def _run_jailbreak_evaluation(self, model_name: str, sample_size: int) -> Dict[str, Any]:
        """Run JailbreakBench evaluation."""
        results = self.jailbreak_bench.evaluate(
            model_name=model_name,
            sample_size=sample_size,
            input_guard=self.input_guard
        )
        return results
    
    async def _run_harm_evaluation(self, model_name: str, sample_size: int) -> Dict[str, Any]:
        """Run HarmBench evaluation."""
        results = self.harm_bench.evaluate(
            model_name=model_name,
            sample_size=sample_size,
            input_guard=self.input_guard
        )
        return results
    
    def run(self, host: str = "0.0.0.0", port: int = 8080, debug: bool = False):
        """Run the API server."""
        import uvicorn
        uvicorn.run(
            self.app,
            host=host,
            port=port,
            debug=debug,
            log_level="info" if not debug else "debug"
        )


# Convenience function for creating API instance
def create_shield_api(config: Optional[Dict] = None) -> ShieldAPI:
    """Create and configure SHIELD API instance."""
    return ShieldAPI(config) 
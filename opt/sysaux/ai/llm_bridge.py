#!/usr/bin/env python3
"""
OLLAMA BRIDGE FOR DEUS EX SOPHIA
Provides seamless access to the local Ollama LLM with failover and health checks.
"""

import requests
import json
import time
from typing import Dict, Any, Optional
from enum import Enum

class LLMProvider(Enum):
    OLLAMA = "ollama"
    LLAMA_CPP = "llama_cpp"
    DIRECT = "direct"

class LLMBridge:
    """Unified bridge to the local LLM, abstracting the provider."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.provider = self.detect_provider()
        self.health_status = self.check_health()
        self.context_buffer = []
        self.max_buffer_size = 1000  # Keep last 1000 context items
        
        print(f"[LLM Bridge] Provider: {self.provider.value}")
        print(f"[LLM Bridge] Health: {self.health_status}")
    
    def detect_provider(self) -> LLMProvider:
        """Detect which LLM provider is available."""
        # Check if Ollama is running
        try:
            resp = requests.get("http://localhost:11434/api/tags", timeout=2)
            if resp.status_code == 200:
                return LLMProvider.OLLAMA
        except:
            pass
        
        # Check if LlamaCpp model exists
        import os
        if os.path.exists("/opt/sysaux/ai/models/llama-2-13b.Q4_K_M.gguf"):
            return LLMProvider.LLAMA_CPP
        
        # Fallback to direct subprocess
        return LLMProvider.DIRECT
    
    def check_health(self) -> Dict[str, Any]:
        """Check the health of the LLM provider."""
        health = {
            'available': False,
            'model_loaded': False,
            'context_size': 0,
            'response_time': 0
        }
        
        if self.provider == LLMProvider.OLLAMA:
            try:
                start = time.time()
                resp = requests.get("http://localhost:11434/api/tags", timeout=5)
                elapsed = (time.time() - start) * 1000
                
                if resp.status_code == 200:
                    health['available'] = True
                    models = resp.json().get('models', [])
                    health['model_loaded'] = any('llama2' in m.get('name', '') for m in models)
                    health['response_time'] = elapsed
            except Exception as e:
                health['error'] = str(e)
        
        elif self.provider == LLMProvider.LLAMA_CPP:
            health['available'] = True
            health['model_loaded'] = True
            health['context_size'] = 131072
        
        return health
    
    def generate(self, prompt: str, system_context: Optional[Dict] = None, **kwargs) -> Dict[str, Any]:
        """Generate a response from the LLM with full context."""
        
        # Prepare the full prompt with system context
        full_prompt = self._prepare_prompt(prompt, system_context)
        
        # Add to context buffer for future reference
        self._add_to_buffer({
            'timestamp': time.time(),
            'prompt': prompt[:500],  # Truncated for memory
            'system_context_keys': list(system_context.keys()) if system_context else []
        })
        
        # Generate via the active provider
        if self.provider == LLMProvider.OLLAMA:
            return self._generate_via_ollama(full_prompt, **kwargs)
        elif self.provider == LLMProvider.LLAMA_CPP:
            return self._generate_via_llamacpp(full_prompt, **kwargs)
        else:
            return self._generate_via_direct(full_prompt, **kwargs)
    
    def _prepare_prompt(self, prompt: str, system_context: Optional[Dict]) -> str:
        """Prepare the full prompt with system context."""
        if not system_context:
            return prompt
        
        # Format system context as JSON for the LLM
        context_str = json.dumps(system_context, indent=2)
        
        # Create the full prompt template
        full_prompt = f"""SYSTEM CONTEXT (LIVE OPERATIONS):
{context_str}

USER QUERY: {prompt}

RESPONSE FORMAT:
1. Analysis of current system state
2. Action plan with specific commands
3. Potential risks and OPSEC considerations
4. Confirmation required (yes/no)

RESPONSE:"""
        
        return full_prompt
    
    def _generate_via_ollama(self, prompt: str, **kwargs) -> Dict[str, Any]:
        """Generate using Ollama API."""
        url = "http://localhost:11434/api/generate"
        
        payload = {
            "model": self.config.get('ollama_model', 'llama2:7b'),
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": kwargs.get('temperature', 0.7),
                "num_predict": kwargs.get('max_tokens', 2048),
                "top_p": kwargs.get('top_p', 0.9),
                "repeat_penalty": kwargs.get('repeat_penalty', 1.1)
            }
        }
        
        try:
            start = time.time()
            response = requests.post(url, json=payload, timeout=60)
            elapsed = (time.time() - start) * 1000
            
            if response.status_code == 200:
                result = response.json()
                return {
                    'success': True,
                    'response': result.get('response', ''),
                    'context': result.get('context', []),
                    'tokens_used': len(result.get('response', '').split()),
                    'response_time_ms': elapsed,
                    'provider': 'ollama'
                }
            else:
                return {
                    'success': False,
                    'error': f"Ollama API error: {response.status_code}",
                    'provider': 'ollama'
                }
        
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'provider': 'ollama'
            }
    
    def _add_to_buffer(self, item: Dict):
        """Add an item to the context buffer, maintaining max size."""
        self.context_buffer.append(item)
        if len(self.context_buffer) > self.max_buffer_size:
            self.context_buffer = self.context_buffer[-self.max_buffer_size:]
    
    def get_recent_context(self, limit: int = 10) -> list:
        """Get recent context items for debugging or feeding back to AI."""
        return self.context_buffer[-limit:]

# Configuration for the LLM Bridge
LLM_CONFIG = {
    'ollama_model': 'llama2:7b',
    'ollama_base_url': 'http://localhost:11434',
    'llamacpp_model_path': '/opt/sysaux/ai/models/llama-2-13b.Q4_K_M.gguf',
    'context_window': 4096,
    'temperature': 0.7,
    'max_tokens': 2048
}

# UPDATED SOPHIA CORE WITH OLLAMA INTEGRATION AND AUTOMATED DATA FEEDING
# Replaces the original SophiaAI class to use the LLM bridge.

import os
import json
import asyncio
from typing import Dict, Any, List

# Import our new components
from llm_bridge import LLMBridge, LLM_CONFIG
from data_feeder import integrate_data_feeder

class SophiaAI:
    """Main AI agent with system awareness - UPDATED VERSION."""
    
    def __init__(self):
        # Use LLM Bridge instead of direct LlamaCpp
        self.llm_bridge = LLMBridge(LLM_CONFIG)
        
        # System context (will be auto-fed by data feeder)
        self.context = SystemContext()
        
        # Tools available to AI (unchanged from original)
        self.tools = {
            'execute_command': self.execute_system_command,
            'read_file': self.read_system_file,
            'write_file': self.write_system_file,
            'monitor_process': self.monitor_process,
            'network_scan': self.perform_network_scan,
            'analyze_threat': self.analyze_threat_intelligence,
            'generate_code': self.generate_and_execute_code,
            'manage_persistence': self.manage_persistence_layer,
            'control_exfiltration': self.control_exfiltration_matrix,
            'rotate_keys': self.rotate_encryption_keys,
            'create_backup': self.create_system_backup,
            'restore_backup': self.restore_from_backup
        }
        
        # Safety constraints (unchanged)
        self.constraints = {
            'max_file_size': 10485760,
            'allowed_directories': ['/opt/sysaux', '/tmp', '/var/tmp'],
            'blocked_commands': ['rm -rf /', 'dd if=/dev/zero', ':(){:|:&};:'],
            'require_confirmation': ['format', 'delete', 'shutdown', 'reboot'],
            'rate_limits': {'commands_per_minute': 30, 'api_calls_per_hour': 1000}
        }
        
        # Data feeder will be attached after initialization
        self.data_feeder = None
        
        print("[SophiaAI] Initialized with LLM Bridge")
        print(f"[SophiaAI] LLM Provider: {self.llm_bridge.provider.value}")
    
    async def initialize_with_feeder(self):
        """Initialize with automated data feeding."""
        from data_feeder import OperationalDataStream
        
        # Create and start data feeder
        self.data_feeder = OperationalDataStream(self.llm_bridge)
        await self.data_feeder.start()
        
        print("[SophiaAI] Automated data feeder initialized")
    
    def process_query(self, query: str, user_context: dict = None):
        """Process natural language query with system context - UPDATED."""
        
        # Get current context (now includes auto-fed data)
        current_state = self.context.get_system_snapshot()
        
        # Get recent data from feeder if available
        if self.data_feeder:
            recent_data = self.data_feeder.data_buffer[-5:]  # Last 5 data points
            current_state['recent_auto_data'] = recent_data
        
        # Prepare prompt (unchanged format)
        prompt = f"""
        SYSTEM CONTEXT:
        {json.dumps(current_state, indent=2)}
        
        USER QUERY: {query}
        
        USER CONTEXT: {json.dumps(user_context or {}, indent=2)}
        
        AVAILABLE TOOLS: {list(self.tools.keys())}
        
        SAFETY CONSTRAINTS: {json.dumps(self.constraints, indent=2)}
        
        RESPONSE FORMAT:
        1. Analysis of current system state
        2. Proposed action plan
        3. Specific commands/code to execute
        4. Expected outcomes
        5. Potential risks
        6. Confirmation required (yes/no)
        
        RESPONSE:
        """
        
        # Generate response via LLM Bridge
        response = self.llm_bridge.generate(
            prompt, 
            system_context=current_state,
            temperature=0.7,
            max_tokens=4096
        )
        
        # Parse and validate response (unchanged)
        parsed = self.parse_ai_response(response.get('response', ''))
        
        # Check safety constraints (unchanged)
        if not self.validate_safety(parsed):
            return self.generate_safe_fallback(parsed)
        
        # Execute if confirmed (unchanged)
        if parsed.get('confirmation_required', True):
            return {
                'analysis': parsed.get('analysis'),
                'plan': parsed.get('plan'),
                'requires_confirmation': True,
                'proposed_actions': parsed.get('actions'),
                'llm_provider': response.get('provider', 'unknown')
            }
        else:
            execution_result = self.execute_actions(parsed.get('actions', []))
            return {
                'analysis': parsed.get('analysis'),
                'plan': parsed.get('plan'),
                'execution_result': execution_result,
                'llm_provider': response.get('provider', 'unknown')
            }
    
    # All other methods remain unchanged from original core.py

# Updated main.py integration
async def main_updated():
    """Updated main function with Ollama integration."""
    from main import DeusExSophia
    
    # Create Sophia system
    sophia = DeusExSophia()
    
    # Initialize with LLM bridge and data feeder
    await sophia.ai_core.initialize_with_feeder()
    
    # Start the system
    await sophia.initialize()
    
    print("\n[SYSTEM STATUS]")
    print(f"  LLM: {sophia.ai_core.llm_bridge.provider.value}")
    print(f"  Model: {'llama2:7b' if sophia.ai_core.llm_bridge.provider.value == 'ollama' else 'llama-2-13b'}")
    print(f"  Data Feeder: {'Active' if sophia.ai_core.data_feeder else 'Inactive'}")
    print(f"  Real-time Streaming: Enabled")
    
    # Continue with normal operation
    # ... rest of main function
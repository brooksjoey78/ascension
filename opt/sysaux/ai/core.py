```python
# /opt/sysaux/ai/core.py
class SophiaAI:
    """Main AI agent with system awareness"""
    
    def __init__(self):
        # Local LLM (privacy preserving)
        self.llm = LlamaCpp(
            model_path="/opt/sysaux/ai/models/llama-2-13b.Q4_K_M.gguf",
            n_ctx=131072,
            n_threads=os.cpu_count(),
            n_gpu_layers=0,  # CPU only for security
            verbose=False
        )
        
        # System context
        self.context = SystemContext()
        
        # Tools available to AI
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
        
        # Safety constraints
        self.constraints = {
            'max_file_size': 10485760,  # 10MB
            'allowed_directories': ['/opt/sysaux', '/tmp', '/var/tmp'],
            'blocked_commands': ['rm -rf /', 'dd if=/dev/zero', ':(){:|:&};:'],
            'require_confirmation': ['format', 'delete', 'shutdown', 'reboot'],
            'rate_limits': {'commands_per_minute': 30, 'api_calls_per_hour': 1000}
        }
    
    def process_query(self, query: str, user_context: dict = None):
        """Process natural language query with system context"""
        
        # Update context with current system state
        current_state = self.context.get_system_snapshot()
        
        # Prepare prompt with full context
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
        
        # Generate response
        response = self.llm(prompt, max_tokens=4096, temperature=0.7)
        
        # Parse and validate response
        parsed = self.parse_ai_response(response)
        
        # Check safety constraints
        if not self.validate_safety(parsed):
            return self.generate_safe_fallback(parsed)
        
        # Execute if confirmed
        if parsed.get('confirmation_required', True):
            return {
                'analysis': parsed.get('analysis'),
                'plan': parsed.get('plan'),
                'requires_confirmation': True,
                'proposed_actions': parsed.get('actions')
            }
        else:
            return self.execute_actions(parsed.get('actions', []))
    
    def execute_system_command(self, command: str, timeout: int = 30):
        """Execute system command with safety checks"""
        
        # Validate command against constraints
        if not self.validate_command(command):
            raise SecurityError(f"Command blocked by safety constraints: {command}")
        
        # Execute in constrained environment
        import subprocess
        import shlex
        
        try:
            # Use prlimit to constrain resources
            process = subprocess.run(
                shlex.split(command),
                timeout=timeout,
                capture_output=True,
                text=True,
                preexec_fn=lambda: self.set_process_limits()
            )
            
            return {
                'success': process.returncode == 0,
                'returncode': process.returncode,
                'stdout': process.stdout,
                'stderr': process.stderr,
                'execution_time': process.elapsed.total_seconds()
            }
            
        except subprocess.TimeoutExpired:
            raise TimeoutError(f"Command timed out after {timeout} seconds")
        except Exception as e:
            raise ExecutionError(f"Command execution failed: {str(e)}")
    
    def generate_and_execute_code(self, requirements: str, language: str = "python"):
        """Generate and execute code based on requirements"""
        
        # Generate code
        code_prompt = f"""
        Generate {language} code that satisfies these requirements:
        {requirements}
        
        Constraints:
        1. Must run in isolated sandbox
        2. Maximum execution time: 60 seconds
        3. No network access unless explicitly required
        4. No filesystem writes outside /tmp
        5. Include error handling
        6. Include logging
        
        Code:
        """
        
        generated_code = self.llm(code_prompt, max_tokens=2048, temperature=0.3)
        
        # Validate code
        if not self.validate_code(generated_code, language):
            raise SecurityError("Generated code failed security validation")
        
        # Execute in sandbox
        if language == "python":
            return self.execute_python_sandbox(generated_code)
        elif language == "bash":
            return self.execute_bash_sandbox(generated_code)
        else:
            raise ValueError(f"Unsupported language: {language}")
```
```python
# /opt/sysaux/ai/communication.py
class AICommunication:
    """Multi-modal communication interface"""
    
    def __init__(self):
        # WebSocket server for real-time updates
        self.websocket_server = WebSocketServer(
            port=8765,
            ssl_context=self.create_ssl_context(),
            max_connections=10
        )
        
        # REST API
        self.api_server = APIServer(
            port=8080,
            routes=self.define_api_routes(),
            auth_middleware=self.jwt_auth_middleware
        )
        
        # Voice interface
        self.voice_engine = VoiceEngine(
            tts_model="/opt/sysaux/ai/models/tts.pt",
            stt_model="/opt/sysaux/ai/models/stt.pt",
            language="en",
            voice="sophia"
        )
        
        # Notification system
        self.notifier = Notifier(
            channels=['websocket', 'email', 'sms', 'push'],
            priority_levels=['low', 'medium', 'high', 'critical']
        )
    
    def define_api_routes(self):
        """Define AI API endpoints"""
        return {
            # System interaction
            'POST /api/v1/ai/query': self.handle_query,
            'GET /api/v1/ai/status': self.get_ai_status,
            'POST /api/v1/ai/command': self.execute_command,
            'GET /api/v1/ai/context': self.get_system_context,
            
            # Code generation
            'POST /api/v1/ai/code/generate': self.generate_code,
            'POST /api/v1/ai/code/execute': self.execute_code,
            'GET /api/v1/ai/code/history': self.get_code_history,
            
            # System management
            'POST /api/v1/ai/system/snapshot': self.create_snapshot,
            'GET /api/v1/ai/system/metrics': self.get_system_metrics,
            'POST /api/v1/ai/system/action': self.system_action,
            
            # Threat intelligence
            'GET /api/v1/ai/threats': self.get_threat_analysis,
            'POST /api/v1/ai/threats/respond': self.threat_response,
            
            # Learning and adaptation
            'POST /api/v1/ai/learn': self.add_to_knowledge_base,
            'GET /api/v1/ai/knowledge': self.query_knowledge_base,
            
            # Voice interface
            'POST /api/v1/ai/voice/speak': self.text_to_speech,
            'POST /api/v1/ai/voice/listen': self.speech_to_text,
            
            # Real-time events
            'WS /ws/ai/events': self.websocket_events,
            'WS /ws/ai/terminal': self.websocket_terminal
        }
    
    def websocket_terminal(self, websocket, path):
        """WebSocket terminal for interactive AI control"""
        async def handler():
            async for message in websocket:
                # Parse message
                data = json.loads(message)
                
                if data['type'] == 'command':
                    # Execute command via AI
                    result = await self.ai.process_query(
                        data['command'],
                        user_context=data.get('context', {})
                    )
                    
                    # Send result
                    await websocket.send(json.dumps({
                        'type': 'result',
                        'data': result
                    }))
                
                elif data['type'] == 'stream':
                    # Stream system output
                    async for output in self.stream_system_output(data['stream']):
                        await websocket.send(json.dumps({
                            'type': 'stream_output',
                            'data': output
                        }))
                
                elif data['type'] == 'control':
                    # Control AI behavior
                    self.ai.update_behavior(data['behavior'])
```
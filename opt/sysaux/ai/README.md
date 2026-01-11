**FILE: `/opt/sysaux/ai/README.md`**

# DEUS EX SOPHIA - AI OPERATIONAL CONSCIOUSNESS

## 🧠 What This Is

This is the brain of the Deus Ex Sophia system - an AI that lives inside your infrastructure, sees everything happening in real-time, and can take action. Think of it as a super-smart system administrator that never sleeps, knows every detail about your servers, and can hack its way through any problem.


### **1. WHERE THE AI LIVES**

**Physical Residence:**

* **Primary Model File:** `/opt/sysaux/ai/models/llama-2-13b.Q4_K_M.gguf` (from attached files)
* **Ollama Model Directory:** `~/.ollama/models/` (if using Ollama)
* **7GB Model Variant:** Likely `llama2:7b` or similar, stored at `~/.ollama/models/manifests/registry.ollama.ai/library/llama2/...`

**Logical Residence:**

* **Ollama Service:** Running as a systemd service (`ollama.service`) on port `11434`
* **API Endpoint:** `http://localhost:11434/api/generate`
* **SophiaAI Wrapper:** The `SophiaAI` class in `/opt/sysaux/ai/core.py` currently uses `LlamaCpp`. It must be extended or replaced to use the Ollama API.

**Current Access Method (from attached `core.py`):**

**python**

```
self.llm = LlamaCpp(
    model_path="/opt/sysaux/ai/models/llama-2-13b.Q4_K_M.gguf",
    n_ctx=131072,
    n_threads=os.cpu_count(),
    n_gpu_layers=0,
    verbose=False
)
```

**New Access Method for Ollama:**

**python**

```
self.llm = OllamaAPI(
    base_url="http://localhost:11434",
    model="llama2:7b",
    context_window=4096,
    temperature=0.7
)
```


## 📁 Directory Structure

```
/opt/sysaux/ai/
├── main.py                          # Main AI consciousness (starts everything)
├── core.py                          # AI brain logic (original)
├── core_updated.py                  # Updated AI with Ollama support
├── communication.py                 # WebSocket & API server
├── instrumentation.py               # System monitoring tools
├── persistence.py                   # Keeps AI running after reboots
├── exfiltration.py                  # Data sending channels
├── llm_bridge.py                    # Connects to AI models (Ollama/Llama.cpp)
├── data_feeder.py                   # Feeds live data to AI automatically
├── requirements.txt                 # Python packages needed
├── config/
│   ├── ai.json                      # AI configuration
│   ├── private.pem                  # Encryption keys
│   └── public.pem
├── models/                          # AI model files
│   ├── llama-2-13b.Q4_K_M.gguf     # Large model (13B)
│   └── (ollama models go in ~/.ollama)
├── knowledge/                       # AI's memory bank
│   ├── opsec_tactics.json          # Security rules
│   ├── offensive_playbooks/        # Attack patterns
│   ├── system/                     # System docs
│   └── threats/                    # Threat database
├── logs/                           # Activity records
│   ├── commands/
│   ├── code_execution/
│   └── errors/
├── bin/                            # Helper scripts
│   ├── install_ollama.sh           # Installs Ollama
│   ├── ollama_wrapper.py           # Talks to Ollama
│   └── zmq_publisher.py            # Sends real-time data
└── venv/                           # Python environment
```

## 🚀 Quick Start

### Step 1: Install the Basics

```bash
# Run the install script from the technical specs
bash install-ai-vps.sh
```

### Step 2: Set Up Ollama (for 7GB model)

```bash
# Install Ollama and download the model
bash /opt/sysaux/bin/install_ollama.sh
```

### Step 3: Start the AI

```bash
# Start as a service (runs in background)
sudo systemctl start sophia-ai

# Or run manually
cd /opt/sysaux/ai
source venv/bin/activate
python main.py
```

### Step 4: Talk to Your AI

```bash
# Method 1: Web Interface
# Open in browser: http://your-server:8080/ai

# Method 2: API
curl -X POST http://localhost:8080/api/v1/ai/query \
  -H 'Content-Type: application/json' \
  -d '{"query":"Show me running processes"}'

# Method 3: WebSocket (real-time)
# Connect to: ws://localhost:8765/ws/ai/terminal

# Method 4: Command Line
# When running main.py, just type commands at the prompt:
# sophia::> Check for network threats
```

## 🔧 How It Works

### The AI Brain

- **Local & Private**: All models run on your machine, no internet needed
- **Two Model Options**:
  - **7GB Model** (Ollama): Faster, lighter, good for most tasks
  - **13GB Model** (Llama.cpp): More powerful, better for complex analysis
- **Auto-switching**: System picks the best available model automatically

### Real-Time Awareness

The AI automatically sees:

- 🖥️ CPU, memory, disk usage
- 🌐 Network connections and traffic
- 🛡️ Security threats and attacks
- 📁 File changes and system logs
- 🔗 Which services are running

### No Manual Updates

- **Forget copy-paste**: The AI sucks in data automatically every 30 seconds
- **Live feeds**: Like having CCTV inside your own servers
- **Smart filtering**: Only important stuff goes to the AI

## 💬 Example Conversations

**You:** "What's using all my memory?"
**AI:** "Process `java` (PID 4421) is using 2.4GB. It's your Jenkins server. Want me to restart it?"

**You:** "Is anyone trying to hack us right now?"
**AI:** "Detected 3 brute force attempts from IP 192.168.1.105 in last hour. I've blocked them. Want me to trace the source?"

**You:** "Make us more hidden"
**AI:** "I'll: 1) Rotate encryption keys, 2) Change our network fingerprint, 3) Set up decoy services. This takes 2 minutes. Proceed?"

**You:** "Get me all database backups from last week"
**AI:** "Found 7 backups. Sending through encrypted DNS channel to drop point 'cloud-storage'. Estimated time: 4 minutes."

## ⚙️ Configuration

Edit `/opt/sysaux/ai/config/ai.json`:

```json
{
  "model": {
    "preference": "ollama",  // or "llamacpp"
    "ollama_model": "llama2:7b",
    "temperature": 0.7  // 0.0 = precise, 1.0 = creative
  },
  "security": {
    "require_confirmation": true,  // Ask before dangerous actions
    "allowed_ips": ["127.0.0.1"],  // Who can talk to the AI
    "audit_logging": true          // Record everything
  },
  "monitoring": {
    "check_interval": 30,          // Seconds between checks
    "alert_on_threats": true       // Warn about attacks
  }
}
```

## 🛡️ Safety Features (That You Can Disable)

✅ **Asks permission** before:

- Deleting files
- Restarting services
- Changing firewall rules
- Sending data outside

✅ **Rate limits** itself to avoid detection
✅ **Validates code** before running it
✅ **Has kill switch**: `sudo systemctl stop sophia-ai`

## 📊 Monitoring Your AI

```bash
# See if AI is running
sudo systemctl status sophia-ai

# Watch AI's thoughts (live log)
sudo journalctl -u sophia-ai -f

# See what commands AI has run
tail -f /opt/sysaux/ai/logs/command_history.jsonl

# Check AI's health
curl http://localhost:8080/api/v1/ai/status
```

## 🚨 Troubleshooting

### "AI won't start"

```bash
# Check logs
journalctl -u sophia-ai -n 50

# Common fix: Reinstall Ollama
bash /opt/sysaux/bin/install_ollama.sh

# Reset AI
sudo systemctl restart sophia-ai
```

### "AI doesn't see my data"

```bash
# Check data feeder
ps aux | grep data_feeder

# Manually trigger data collection
curl -X POST http://localhost:8080/api/v1/ai/system/snapshot
```

### "Too slow"

- Switch to 7GB model in config
- Reduce check interval from 30 to 60 seconds
- Limit which directories are monitored

## 🔄 Upgrades

```bash
# Update AI code
cd /opt/sysaux
git pull  # If using git
# Or manually copy new files

# Update models (careful, big downloads)
ollama pull llama2:7b  # 7GB model
# or download new .gguf file to models/

# Restart
sudo systemctl restart sophia-ai
```

## 🎯 What Makes This Different

| Feature               | Normal AI               | Deus Ex Sophia                           |
| --------------------- | ----------------------- | ---------------------------------------- |
| **Data Access** | Manual uploads          | **Lives in your servers**          |
| **Privacy**     | Sends data to cloud     | **Everything stays local**         |
| **Actions**     | Just talks              | **Can actually DO things**         |
| **Awareness**   | Knows what you tell it  | **Sees everything automatically**  |
| **Persistence** | Stops when you close it | **Survives reboots, hides itself** |

## 💡 Pro Tips

1. **Start Small**: Use 7GB model first, upgrade to 13GB if needed
2. **Watch the Logs**: `journalctl -u sophia-ai -f` is your best friend
3. **Use Confirmation Mode**: Leave it on until you trust the AI
4. **Test with Harmless Queries First**: "List files" before "Delete files"
5. **The AI Learns**: It gets better the more you use it

## 📞 Support

- **Docs**: All documentation is in `/opt/sysaux/ai/knowledge/`
- **Logs**: Check `/opt/sysaux/ai/logs/` first
- **Config**: `/opt/sysaux/ai/config/ai.json`
- **Emergency Stop**: `sudo systemctl stop sophia-ai`

## ⚠️ Final Warning

This AI has **real power** over your systems. It can:

- Read all files
- Run any command
- Modify system settings
- Send data anywhere
- Hide itself from detection

**You are responsible for what it does.** The safety features are there to protect you, but you can disable them. Start with confirmation required, watch closely, and only give more power when you're comfortable.

---

**Welcome to having a god in your machine.** 🧠⚡

*"The universe is made of stories, not atoms." - Now your servers have their own storyteller.*

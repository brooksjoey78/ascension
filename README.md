# Ascension

Deus Ex Sophia Project - Ubuntu 22.04 Ascension v4.0

## Project Structure

```
ascention/
├── sophia/              # Main deployment phases
│   ├── phases-1-3.sh   # Foundation, Truth, and Persistence
│   ├── phases-4.sh     # Network Intelligence Expansion
│   ├── phases-5.sh     # Advanced Exfiltration Matrix
│   └── README.md       # Phase documentation
├── scripts/             # Utility scripts
├── requirements.txt     # Python dependencies
└── README.md           # This file
```

## Setup

Install dependencies:
```bash
pip install -r requirements.txt
```

## Deployment

### Option 1: Direct Execution (Ubuntu 22.04)

Run phases as root:
```bash
sudo bash sophia/phases-1-3.sh
sudo bash sophia/phases-4.sh
sudo bash sophia/phases-5.sh
```

This will create the structure documented in `README-1.md` at `/opt/sysaux/`.

### Option 2: Docker Build

Build the Docker image:
```bash
./build.sh
```

Or manually:
```bash
docker build -t deusexsophia/ascension:5.0 .
docker run -d --name sophia --privileged -p 8080:8080 deusexsophia/ascension:5.0
```

The phase scripts will execute automatically when the container starts (if `SOPHIA_AUTO_START=true`).

## Phases

### Phase 1-3: Foundation, Truth, and Persistence
- Environment sanitization
- Core installation with enhanced truth module
- Multi-vector persistence engine

### Phase 4: Network Intelligence Expansion
- Passive intelligence module
- Active reconnaissance
- Threat intelligence

### Phase 5: Advanced Exfiltration Matrix
- Quantum encryption layer
- Multiple exfiltration channels
- Stealth operations

## Requirements

- Ubuntu 22.04
- Root access
- Internet connection
- See `requirements.txt` for Python dependencies

<div align="center">
  <img src="https://raw.githubusercontent.com/FortAwesome/Font-Awesome/6.x/svgs/solid/satellite-dish.svg" width="80" alt="Reconesis Icon"/>
  <h1>Reconesis</h1>
  <p><strong>An Adaptive Agentic Tool for Autonomous Network Reconnaissance</strong></p>

  <p>
    <a href="#about">About</a> •
    <a href="#features">Features</a> •
    <a href="#architecture">Architecture</a> •
    <a href="#installation">Installation</a> •
    <a href="#usage">Usage</a>
  </p>
</div>

---

## 🔍 About

**Reconesis** represents a paradigm shift from traditional static vulnerability scanning to dynamic, agentic reconnaissance. By coupling industry-standard network tools (Nmap) with the cognitive capabilities of Large Language Models (LLMs), Reconesis executes an autonomous **Observe-Orient-Decide-Act (OODA)** loop. 

Unlike linear scripts that generate significant noise and alert fatigue, Reconesis contextually analyzes live findings, prioritizes critical infrastructure (Routers, Firewalls, Mail Servers, Databases), and fine-tunes its scanning strategy on the fly. 

This project aims to automate the decision-making processes inherent in network footprinting while maintaining the speed of standard automation and reducing analyst cognitive load.

---

## ✨ Features

- **🧠 Recursive Agentic Execution**: Replaces static automation with a context-aware LLM State Machine that dynamically writes its own Nmap strategies based on prior scan feedback.
- **⚡ TOON Middleware**: Converts unstructured XML execution output into a token-optimized **Target-Oriented Object Notation (TOON)**, bridging the gap between CLI tools and LLM context windows.
- **🎯 Dynamic Criticality Assessment**: A weighted multi-signal engine that autonomously classifies hosts against four critical infrastructure profiles (Routers, Firewalls, Mail Servers, Database Servers) using port combos, service names, and OS fingerprints.
- **🔄 Context-Aware Prompt Switching**: Automatically transitions from broad, fast "Scout Mode" network sweeps into deep, vulnerability-specific "Hunter Mode" investigations against high-value targets.
- **📈 Comprehensive Dashboard**: Includes a responsive web interface built on Flask and SSE for real-time tracking of scanning phases, live logs, host mapping, and performance metrics.
- **🛑 Adaptive Termination**: Built-in algorithmic exit conditions based on depth exhaustion, hash saturation, and criticality fulfillment to prevent infinite scanning loops.

---

## 🏗️ System Architecture

Reconesis follows a 4-phase non-linear state machine transition sequence:

1. **Phase 1 (Discovery / Scout Mode):** Leverages aggressive SYN and ICMP sweeps to rapidly map live hosts across the target subnet while minimizing overhead.
2. **Phase 2 (Assessment / Scout Mode):** Performs top-level port scanning to identify services. The custom *CriticalityAssessor* algorithm scores the targets and filters out low-value "noise" endpoints (e.g., standard workstations/printers).
3. **Phase 3 (Deep Scan / Hunter Mode):** Triggers specific contextual LLM prompts tailored to the exact asset type discovered. Executes targeted Nmap Scripting Engine (NSE) vulnerability checks.
4. **Phase 4 (Reporting):** The AI Agent evaluates the aggregated TOON mapping data to generate a complete Markdown vulnerability report prioritizing remediation tasks.

---

## 🚀 Installation

Reconesis requires Python 3.9+, Docker (for the demo environment), and Nmap.

### 🐧 Ubuntu / Debian Quick Start

To instantly install all Linux system dependencies (`nmap`, `docker`, `python3-venv`) and configure the environment, run the setup script:

```bash
chmod +x setup.sh
./setup.sh
```

### 💻 Manual Installation (Any OS)

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/reconesis.git
   cd reconesis
   ```
2. **Install Nmap:** Ensure Nmap is installed and available in your system `$PATH`. 
   - Linux: `sudo apt install nmap`
   - Windows/Mac: Download from [Nmap.org](https://nmap.org).
3. **Setup Virtual Environment:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```
4. **Configure API Keys:**
   Copy the example environment file and insert your Groq API key:
   ```bash
   cp .env.example .env
   # Edit .env and set GROQ_API_KEY
   ```

---

## 🎯 Usage

Reconesis provides two interfaces for execution:

### Option A: The Web Dashboard (Recommended)
Launch the interactive visual dashboard which features real-time Server-Sent Events (SSE) telemetry.

```bash
# Note: sudo is generally required on Linux to allow Nmap raw socket (SYN) access
sudo python dashboard.py
```
*Open `http://localhost:5000` in your browser.*

### Option B: The Command Line Interface
Execute headless automated reconnaissance directly from the terminal.

```bash
sudo python main.py --target 192.168.1.0/24
```

---

## 🧪 Interactive Docker Lab

Reconesis includes an isolated 10-container Docker bridge network (`172.20.0.0/24`) designed specifically to demonstrate the agent against simulated vulnerable infrastructure (Database, Mail, Router, Firewall) without scanning live subnets. 

To start the training lab:
```bash
cd demo_lab
docker-compose up -d
```
Once the containers are running, point Reconesis at `172.20.0.0/24`. The agent will systematically ignore the 4 "noise" workstations while deploying Hunter Mode against the 4 critical assets. 

See the [demo_lab/README.md](demo_lab/README.md) for full details on the lab architecture and expected outcomes.

---

## ⚙️ Configuration & Evaluation Metrics

Reconesis tracks three primary Evaluation Criteria natively, logging them to the dashboard and standard output:
1. **Efficiency (Time-to-Insight)**
2. **Traffic Volume (Packets Sent)**
3. **Decision Accuracy (High-value Target Identification)**

You can configure execution limits and underlying API settings directly in `src/utils/config.py`. 

---

<div align="center">
  <small>Developed for AI-Driven Defensive Security Operations</small>
</div>

#!/bin/bash
# ─────────────────────────────────────────────
# Reconesis — Ubuntu Setup Script
# ─────────────────────────────────────────────
set -e

echo "══════════════════════════════════════════"
echo "  Reconesis: Ubuntu Environment Setup"
echo "══════════════════════════════════════════"

# 1. System dependencies
echo "[1/4] Installing system dependencies..."
sudo apt-get update -qq
sudo apt-get install -y nmap python3 python3-pip python3-venv docker.io docker-compose

# 2. Enable Docker (if not already)
echo "[2/4] Enabling Docker..."
sudo systemctl enable docker
sudo systemctl start docker
sudo usermod -aG docker $USER

# 3. Python dependencies
echo "[3/4] Installing Python dependencies..."
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 4. Environment file
echo "[4/4] Setting up environment..."
if [ ! -f .env ]; then
    cp .env.example .env
    echo "⚠️  Created .env from template. Please edit it and add your GROQ_API_KEY."
else
    echo "✅ .env already exists."
fi

echo ""
echo "══════════════════════════════════════════"
echo "  Setup complete!"
echo ""
echo "  Next steps:"
echo "    1. Edit .env and add your GROQ_API_KEY"
echo "    2. Log out and back in (for Docker group)"
echo "       OR run: newgrp docker"
echo "    3. cd demo_lab && docker-compose up -d"
echo "    4. source venv/bin/activate"
echo "    5. sudo python3 main.py --target 172.20.0.0/24"
echo "       OR: python3 dashboard.py"
echo "══════════════════════════════════════════"

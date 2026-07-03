#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Argus OSINT Platform — Termux (Android) bootstrap script
# 100% free, runs on any Android phone with Termux installed
# ─────────────────────────────────────────────────────────────────────────────
# Usage:
#   1. Install Termux from F-Droid (NOT Play Store — outdated)
#   2. Open Termux, run:
#        pkg update && pkg upgrade -y
#        pkg install git python turso-repo -y
#        git clone https://github.com/marwannaili237/Argus.git
#        cd Argus
#        bash termux_setup.sh
#   3. Edit argus/.env to set TELEGRAM_BOT_TOKEN (get one from @BotFather)
#   4. Start Argus: cd argus && python main.py
#   5. Open http://localhost:8000 in any mobile browser
# ─────────────────────────────────────────────────────────────────────────────
set -e

echo "🦅 Argus OSINT — Termux setup starting..."

# Install Termux packages
pkg install -y python python-pip git openssl libxml2 libxslt 2>&1 | tail -5

# Some Termux-specific build deps
pkg install -y libjpeg-turbo libpng zlib 2>&1 | tail -3 || true

# Create .env from example if missing
if [ ! -f argus/.env ]; then
    if [ -f argus/.env.example ]; then
        cp argus/.env.example argus/.env
        echo "✓ Created argus/.env from template"
    else
        # Create a minimal .env
        mkdir -p argus
        cat > argus/.env << 'EOF'
TELEGRAM_BOT_TOKEN=
GEMINI_API_KEY=
SESSION_SECRET=$(openssl rand -hex 32)
MAX_CONCURRENT_PLUGINS=2
INVESTIGATION_TIMEOUT_SECONDS=180
DATA_RETENTION_DAYS=30
EOF
        echo "✓ Created minimal argus/.env"
    fi
fi

# Generate a SESSION_SECRET if empty
if grep -q "^SESSION_SECRET=$" argus/.env; then
    SECRET=$(openssl rand -hex 32)
    sed -i "s/^SESSION_SECRET=$/SESSION_SECRET=$SECRET/" argus/.env
    echo "✓ Generated SESSION_SECRET"
fi

# Termux-specific env tuning (low-end Android, ~2-4GB RAM)
if ! grep -q "MAX_CONCURRENT_PLUGINS" argus/.env; then
    echo "MAX_CONCURRENT_PLUGINS=2" >> argus/.env
    echo "✓ Set MAX_CONCURRENT_PLUGINS=2 (low-end optimized)"
fi
if ! grep -q "INVESTIGATION_TIMEOUT_SECONDS" argus/.env; then
    echo "INVESTIGATION_TIMEOUT_SECONDS=180" >> argus/.env
    echo "✓ Set INVESTIGATION_TIMEOUT_SECONDS=180 (generous for slow mobile network)"
fi

# Install Python deps
echo "📦 Installing Python dependencies (this takes ~3-5 min on phones)..."
pip install --upgrade pip setuptools wheel 2>&1 | tail -2
pip install -e . 2>&1 | tail -10

# Verify install
echo ""
echo "🔍 Verifying install..."
cd argus && python -c "from plugins.runner import classify_target; print('classify_target works:', classify_target('example.com'))"

echo ""
echo "✅ Argus OSINT setup complete!"
echo ""
echo "Next steps:"
echo "  1. Edit argus/.env — set TELEGRAM_BOT_TOKEN (from @BotFather)"
echo "  2. Optional: set GEMINI_API_KEY for AI reports"
echo "  3. Start: cd argus && python main.py"
echo "  4. Open http://localhost:8000 in your mobile browser"
echo ""
echo "🦅 Happy hunting!"

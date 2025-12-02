#!/bin/bash
# Setup script for Zuck Agent with LangChain Tools

echo "🔧 Setting up Zuck Agent with Tools..."

# Activate virtual environment
if [ -d ".venv" ]; then
    echo "✓ Activating virtual environment..."
    source .venv/bin/activate
else
    echo "⚠️  Virtual environment not found. Creating one..."
    python3 -m venv .venv
    source .venv/bin/activate
fi

# Install all dependencies
echo "📦 Installing dependencies..."
pip install -r requirements.txt

echo ""
echo "✅ Setup complete!"
echo ""
echo "To use the agent:"
echo "  1. Activate the environment: source .venv/bin/activate"
echo "  2. Run the agent: python main.py"
echo ""
echo "Available tools:"
echo "  - Calculator (subnet calculations, conversions)"
echo "  - VirusTotal (malware/URL reputation)"
echo "  - DateTime (timestamp analysis)"
echo "  - Memory (session context storage)"
echo "  - File Reader (config/log analysis)"
echo "  - HTTP Request (API testing)"
echo "  - DNS Lookup (DNS queries)"
echo "  - WHOIS (domain information)"
echo "  - Python REPL (code execution)"
echo "  - Wikipedia (security concepts)"

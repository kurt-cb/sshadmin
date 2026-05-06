#!/bin/bash

# SSH Certificate Admin - Setup Script

set -e

echo "🔐 SSH Certificate Admin - Setup Script"
echo "========================================"

# Check Python version
python_version=$(python3 --version 2>&1 | awk '{print $2}')
echo "✓ Found Python $python_version"

# Create virtual environment
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
else
    echo "✓ Virtual environment already exists"
fi

# Activate virtual environment
echo "🔄 Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo "📥 Installing dependencies..."
pip install -q -r requirements.txt

# Initialize database
echo "🗄️ Initializing database..."
python3 << 'EOF'
from sshadmin import app, db
with app.app_context():
    db.create_all()
    print("✓ Database initialized")
EOF

# Check for .env file
if [ ! -f ".env" ]; then
    echo "⚙️  Creating .env file from template..."
    cp .env.example .env
    echo "⚠️  Please edit .env with your configuration"
else
    echo "✓ .env file already exists"
fi

echo ""
echo "✅ Setup complete!"
echo ""
echo "Next steps:"
echo "1. Edit .env file with your configuration"
echo "2. Set up SSH CA keys (see README.md)"
echo "3. Run: source venv/bin/activate"
echo "4. Run: python3 sshadmin.py"
echo ""
echo "Access the application at: http://localhost:5000"

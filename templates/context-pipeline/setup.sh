#!/bin/bash
# Context Pipeline Setup
# Run: bash setup.sh

set -e

echo "Setting up Context Pipeline..."

# Create venv
if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv .venv
fi

source .venv/bin/activate

# Install deps
echo "Installing dependencies..."
pip install -q -r requirements.txt

# Test import
echo "Verifying installation..."
python -c "from pipeline import ContextPipeline; print('✓ Pipeline ready')"

echo ""
echo "Setup complete. Usage:"
echo "  source .venv/bin/activate"
echo "  ./ctx 'your query' --compress"
echo ""
echo "Or in Python:"
echo "  from pipeline import ContextPipeline"
echo "  p = ContextPipeline()"
echo "  p.index_workspace()"
echo "  result = p.get_context('query')"

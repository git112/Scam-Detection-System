#!/usr/bin/env bash
# exit on error
set -o errexit

# Install dependencies
pip install -r requirements.txt

# Create uploads directory
mkdir -p uploads

# Print Python version and installed packages for debugging
python --version
pip list

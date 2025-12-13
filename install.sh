#!/bin/bash

# --- Rana_NMAP.py Installation Script for Termux ---

echo "Starting setup for Rana_NMAP.py..."

# 1. Update package list and install Python
pkg update -y
pkg install python -y

# 2. Install required Python libraries
echo "Installing required Python libraries (colorama)..."
pip install colorama

# 3. Grant execution permission to the main script
echo "Setting executable permission for Rana_NMAP.py..."
chmod +x Rana_NMAP.py

# 4. Optional: Create an alias for easy running (like a function)
# This lets the user just type 'nmap_rana' to run the tool.
echo "Creating function 'nmap_rana' to run the tool easily..."

# Check if the alias is already in .bashrc, if not, add it
if ! grep -q "alias nmap_rana='python Rana_NMAP.py'" ~/.bashrc; then
    echo "alias nmap_rana='python Rana_NMAP.py'" >> ~/.bashrc
fi

echo -e "\n--- Setup Complete! ---"
echo "You can now run the script in two ways:"
echo "1. Using the Python command: python Rana_NMAP.py"
echo "2. By reloading Termux and typing: nmap_rana"
echo "-----------------------\n"

# Reload .bashrc to make the new alias/function active immediately
source ~/.bashrc
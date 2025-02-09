#!/bin/bash

echo "Installing Suricata..."
sudo apt-get update
sudo apt-get install -y suricata

echo "Backing up existing Suricata config files..."
sudo cp /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.bak
sudo cp /etc/suricata/classification.config /etc/suricata/classification.config.bak
sudo cp /etc/suricata/threshold.config /etc/suricata/threshold.config.bak

echo "Copying new configuration files from ICADS repo..."
sudo cp config/suricata.yaml /etc/suricata/
sudo cp config/classification.config /etc/suricata/

echo "Copying custom rules..."
sudo cp config/icads.rules /etc/suricata/rules/
sudo cp config/blacklist.txt /etc/suricata/rules/

echo "Setting correct permissions for Suricata rules..."
sudo chmod 644 /etc/suricata/rules/*.rules
sudo chmod 644 /etc/suricata/rules/blacklist.txt

echo "Restarting Suricata..."
sudo systemctl restart suricata
sudo systemctl stop suricata

echo "Copying ICADS.py to Desktop..."
cp src/ICADS.py ~/Desktop/

echo "Creating model directory and copying model file..."
sudo mkdir -p /etc/suricata/model/
sudo cp src/model/random_forest_model.pkl /etc/suricata/model/

echo "Setup complete! Suricata is configured for ICADS"
echo "Please install python and its dependencies, run suricata using -> sudo systemctl start/restart/stop suricata and run ICADS.py"

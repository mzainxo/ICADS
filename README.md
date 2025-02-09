# ICADS - Intelligent Cyber Attacks Detection System

## Overview

**ICADS** is an intelligent cybersecurity system designed to detect and classify DDoS (Distributed Denial of Service) attacks in real-time. By integrating anomaly based detection with the **Suricata IDS**, this project enhances network traffic analysis and threat detection capabilities.

---

## Installation & Setup

### Prerequisites

Ensure the following are installed on your system:

- **Suricata IDS** (compatible with Kali Linux and other platforms)
- **Python 3.x** with **pip**
- **Git**
- **Scikit-learn**, **Pandas**, **NumPy** (see `requirements.txt`)

### Step-by-Step Instructions

#### 1. Clone the Repository

Clone the ICADS repository to your local machine:

```bash
git clone https://github.com/YOUR_USERNAME/ICADS.git
cd ICADS
```

#### 2. Install Python Dependencies
Install the required Python packages:

```bash
pip install -r requirements.txt
```
#### 3. Run the Setup Script
Make the setup_suricata.sh script executable and then execute it:

```bash
chmod +x scripts/setup_suricata.sh
./scripts/setup_suricata.sh
```
#### After running the setup script, you can manage Suricata using the following commands:

#### Start Suricata:

```bash
sudo suricata -c /etc/suricata/suricata.yaml
```
#### Restart Suricata:

```bash
sudo systemctl restart suricata
```
#### Stop Suricata:

```bash
sudo systemctl stop suricata
```
#### Check Suricata Status:
```bash
sudo systemctl status suricata
```

#### View Suricata Alerts (fast.log):
```bash
tail -f /var/log/suricata/fast.log
```
This will display the latest entries in fast.log, where Suricata writes its alerts.

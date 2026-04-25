# Network Security Scanner

## About This Project
A Python-based professional network reconnaissance and vulnerability scanning tool 
that performs host discovery, open port detection, service fingerprinting, and 
OS detection — then generates a complete penetration testing report in both 
console and HTML format. Built to simulate real-world network security assessments 
performed by penetration testers and SOC analysts.

## What Problem Does It Solve?
Security teams need to know exactly what is running on their network — open ports, 
active services, and potential vulnerabilities. This tool automates that entire 
discovery process and produces a clean, structured report ready for security 
review — mimicking professional tools like Nmap but built entirely in Python.

## Features
- Host discovery — checks if a target is online before scanning
- Full port scanning across common and custom port ranges
- Service detection — identifies what is running on each open port
- Banner grabbing — pulls service version information directly from ports
- OS fingerprinting — detects the likely operating system
- Risk rating — assigns LOW / MEDIUM / HIGH risk to each open port
- Console report with visual formatting
- Full HTML report generated automatically
- JSON export of all scan results
- Scan multiple targets at once from a config file

## Technologies Used
- Python 3
- Socket (built-in — no install needed)
- Threading (built-in — no install needed)
- JSON (built-in — no install needed)
- HTML report generation (built-in — no install needed)
- Datetime (built-in — no install needed)

## No External Libraries Required
This tool runs on pure Python standard library — no pip install needed.
Just download and run.

## Real-World Alignment
This project directly mirrors tools and workflows used in professional 
penetration testing and SOC environments:

| This Project | Real World Equivalent |
|---|---|
| Port scanning | Nmap TCP SYN scan |
| Banner grabbing | Netcat / Nmap -sV |
| Service detection | Nmap service fingerprinting |
| OS fingerprinting | Nmap -O flag |
| HTML report | Nmap XML + report tools |
| Multi-target scanning | Enterprise vulnerability scanners |
| Risk rating per port | Tenable Nessus severity ratings |

## How to Run

**Step 1 — Make sure Python is installed**
```bash

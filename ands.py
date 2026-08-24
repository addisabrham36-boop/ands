#!/usr/bin/env python3
"""
ANDS — Anomaly-based Network Detection System
Main Entrypoint Script
"""
import sys
import os
import warnings

# Suppress cryptography / scapy deprecation warnings
warnings.filterwarnings("ignore")

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from core.console import main

if __name__ == "__main__":
    main()

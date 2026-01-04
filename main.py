#!/usr/bin/env python3
"""
Zuck - AI Cybersecurity Agent for Linux Systems
"""

# Suppress noisy warnings BEFORE importing anything
import warnings
import logging
warnings.filterwarnings('ignore')
logging.getLogger('httpx').setLevel(logging.ERROR)
logging.getLogger('httpcore').setLevel(logging.ERROR)
logging.getLogger('langchain').setLevel(logging.ERROR)
logging.getLogger('langchain_google_genai').setLevel(logging.ERROR)

from zuck.cli import main

if __name__ == "__main__":
    main()
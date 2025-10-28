#!/usr/bin/env python3
"""Main entry point for MalwareAnalyzer CLI"""

import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from malanalyzer.cli import cli

if __name__ == '__main__':
    cli.main()

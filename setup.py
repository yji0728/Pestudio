#!/usr/bin/env python3
"""Setup script for MalwareAnalyzer"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="malanalyzer-pro",
    version="1.0.0",
    author="MalwareAnalyzer Team",
    author_email="team@malanalyzer.com",
    description="Advanced PE Dynamic Analysis System",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/malanalyzer/malanalyzer-pro",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.10",
    install_requires=[
        "pefile>=2023.2.7",
        "pycryptodome>=3.19.0",
        "requests>=2.31.0",
        "click>=8.1.7",
        "PyYAML>=6.0.1",
        "colorama>=0.4.6",
        "SQLAlchemy>=2.0.23",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "black>=23.7.0",
            "flake8>=6.1.0",
        ],
        "gui": [
            "PyQt6>=6.6.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "malanalyzer=malanalyzer.cli.cli:main",
        ],
    },
)

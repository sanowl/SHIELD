#!/usr/bin/env python3
"""
Setup script for SHIELD: Comprehensive LLM Adversarial Robustness Framework
"""

from setuptools import setup, find_packages
import os

# Read long description from README
def read_readme():
    try:
        with open("README.md", "r", encoding="utf-8") as fh:
            return fh.read()
    except FileNotFoundError:
        return "SHIELD: Comprehensive LLM Adversarial Robustness Framework"

# Read requirements from requirements.txt
def read_requirements():
    try:
        with open("requirements.txt", "r", encoding="utf-8") as fh:
            return [line.strip() for line in fh if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        return []

setup(
    name="shield-llm",
    version="1.0.0",
    author="San Hashim",
    author_email="san.hashimhama@outlook.com",
    description="Comprehensive LLM Adversarial Robustness Framework",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/shield-team/shield",
    project_urls={
        "Bug Reports": "https://github.com/shield-team/shield/issues",
        "Source": "https://github.com/shield-team/shield",
        "Documentation": "https://shield-llm.readthedocs.io/",
    },
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.9",
    install_requires=read_requirements(),
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.1.0",
            "black>=23.11.0",
            "flake8>=6.1.0",
            "sphinx>=7.0.0",
            "sphinx-rtd-theme>=1.3.0",
        ],
        "cloud-aws": [
            "boto3>=1.34.0",
        ],
        "cloud-azure": [
            "azure-ai-ml>=1.11.0",
        ],
        "cloud-gcp": [
            "google-cloud-aiplatform>=1.38.0",
        ],
        "monitoring": [
            "prometheus-client>=0.19.0",
            "grafana-api>=1.0.3",
        ],
        "benchmark": [
            "datasets>=2.14.0",
            "evaluate>=0.4.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "shield=shield.__main__:cli",
        ],
    },
    include_package_data=True,
    package_data={
        "shield": [
            "config/*.yaml",
            "config/*.json",
            "data/*.json",
            "templates/*.html",
        ],
    },
    zip_safe=False,
    keywords=[
        "llm",
        "adversarial",
        "robustness", 
        "security",
        "jailbreak",
        "prompt-injection",
        "ai-safety",
        "machine-learning",
        "natural-language-processing",
    ],
) 
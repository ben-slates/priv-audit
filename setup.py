"""
Setup configuration for PrivAudit.
"""

from setuptools import setup, find_packages

setup(
    name="priv-audit",
    version="1.0.0",
    author="Ben",
    description="Next-Generation Linux Privilege Escalation Auditor",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/ben/priv-audit",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
    ],
    python_requires=">=3.10",
    install_requires=[
        "colorama>=0.4.6",
        "psutil>=5.9.6",
        "pyyaml>=6.0.1",
        "tabulate>=0.9.0",
    ],
    entry_points={
        "console_scripts": [
            "priv-audit=main:main",
        ],
    },
)
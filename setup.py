
"""Setup script for Digital Forensics Workbench."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="digital-forensics-workbench",
    version="3.0.0",
    author="DFW Team",
    description="Professional digital forensics analysis platform",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourrepo/dfw",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "dfw=dfw.main_app:main",
        ],
    },
    include_package_data=True,
    package_data={
        "dfw": [
            "templates/*.html",
            "yara_rules/*.yar",
            "config/*.json",
        ],
    },
)
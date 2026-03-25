"""NetWatchAI package setup."""

from setuptools import setup, find_packages

with open("README.md", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="netwatchai",
    version="1.0.0",
    author="Udaya K",
    description="AI-powered network monitoring and intrusion detection system",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/udayak/NetWatchAI",
    packages=find_packages(),
    python_requires=">=3.11",
    install_requires=[
        "scapy>=2.5.0",
        "scikit-learn>=1.3.0",
        "pandas>=2.0.0",
        "streamlit>=1.28.0",
        "joblib>=1.3.0",
        "plotly>=5.18.0",
    ],
    entry_points={
        "console_scripts": [
            "netwatchai-train=train:main",
            "netwatchai-capture=capture:main",
            "netwatchai-dashboard=netwatchai_cli:run_dashboard",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["data/*.csv"],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "License :: OSI Approved :: MIT License",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Operating System :: OS Independent",
    ],
    keywords="network security intrusion detection machine learning anomaly ids",
)

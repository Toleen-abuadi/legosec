from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="legosec",
    version="0.1.0",  # Start with a version number
    author="LegoSec Team",
    author_email="toleenabuadi@gmail.com",
    description="A security package for LEGO systems",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Toleen-abuadi/legosec-pypi",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=[
        "asgiref>=3.8.1",
        "cryptography>=44.0.3",
        "Django>=5.0.6",
        "pyOpenSSL>=25.0.0",
        "requests>=2.32.3",
        "channels>=4.1.0",  # For WebSocket support
        "djangorestframework>=3.15.1",  # For REST API
    ],
    extras_require={
        "dashboard": [
            "Django>=5.0.6",
            "channels>=4.1.0",
            "djangorestframework>=3.15.1",
        ],
        "dev": [
            "pytest>=8.3.5",
            "pytest-django>=4.11.1",
        ],
    },
    dependency_links=[
        "git+https://github.com/gesslerpd/pyopenssl-psk.git@895701d6d420d5d1ed2d341d81fa689fd00b4e63#egg=pyopenssl-psk",
    ],
)
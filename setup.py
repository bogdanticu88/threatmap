from setuptools import find_packages, setup

setup(
    name="threatmap",
    version="1.1.3",
    description="Static IaC threat modeler using STRIDE",
    author="Bogdan Ticu",
    author_email="bogdanticuoffice@gmail.com",
    url="https://github.com/bogdanticu88/threatmap",
    license="MIT",
    packages=find_packages(exclude=["tests*"]),
    python_requires=">=3.9",
    install_requires=[
        "python-hcl2>=4.3.0",
        "pyyaml>=6.0.1",
        "click>=8.1.0",
        "rich>=13.0.0",
        "jinja2>=3.1.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
        ]
    },
    entry_points={
        "console_scripts": [
            "threatmap=threatmap.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
    ],
)

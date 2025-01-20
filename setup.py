from setuptools import setup, find_packages

setup(
    name="jasapp",
    version="0.1.2",
    description="A tool for linting Dockerfiles & Kubernetes manifests with scoring capabilities.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Jordan Assouline",
    author_email="jordan.assouline@hotmail.fr",
    url="https://gitlab.com/jassouline/jasapp",


    packages=find_packages(exclude=["tests*"]),
    include_package_data=True,

    install_requires=[
        "pyyaml==6.0.1",
        "setuptools==68.0.0",
        "requests==2.28.2",
        "pytest==8.3.4",
        "flake8==7.1.1",
        "email-validator==2.2.0"
        ],
    entry_points={
        "console_scripts": [
            "jasapp=jasapp.cli:main",
        ],
    },

    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.11",
)

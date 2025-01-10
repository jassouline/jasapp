from setuptools import setup, find_packages

setup(
    name="jasapp",
    version="0.1.0",
    description="A tool for linting Dockerfiles with custom rules.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Jordan Assouline",
    author_email="jordan.assouline@hotmail.fr",
    url="https://gitlab.com/jassouline/jasapp",  # Remplacez par le lien GitHub


    packages=find_packages(exclude=["tests*"]),
    include_package_data=True,

    install_requires=["pyyaml", "email-validator", "pytest", "requests"],
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

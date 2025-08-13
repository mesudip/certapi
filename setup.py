from setuptools import setup, find_packages

setup(
    name="certapi",
    version="0.4.6",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "cryptography",
        "requests",
    ],
    include_package_data=True,
    description="Python Package for managing keys, request SSL certificates from ACME.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Sudip Bhattarai",
    author_email="sudipbhattarai100@gmail.com",
    url="https://github.com/mesudip/certapi",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
)

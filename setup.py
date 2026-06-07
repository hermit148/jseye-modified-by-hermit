from setuptools import setup, find_packages

setup(
    name="jseye",
    version="3.0.1",
    author="Lakshmikanthan K (Modified by H3RM!T)",
    author_email="letchupkt.dev@gmail.com",
    description="JavaScript Intelligence & Attack Surface Discovery Engine (Modified)",
    long_description=open("README.md", encoding="utf-8").read() if open("README.md", encoding="utf-8") else "",
    long_description_content_type="text/markdown",
    url="https://github.com/letchupkt/jseye",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "aiohttp>=3.8.0",
        "beautifulsoup4>=4.11.0",
        "lxml>=4.9.0",
        "jsbeautifier>=1.14.0",
        "jinja2>=3.1.0",
        "waybackpy>=3.0.6",
        "tldextract>=3.4.0",
        "rich>=12.0.2",
        "psutil>=5.9.0",
        "requests>=2.28.0",
        "tldextract>=3.4.0",
    ],
    extras_require={
        "headless": [
            "playwright>=1.30.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "jseye=jseye.cli:cli_main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
)

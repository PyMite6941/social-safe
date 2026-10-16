from setuptools import setup, find_packages

setup(
    name="socialsafe",
    version="0.1.0",
    author="pymite6941",
    author_email="you@example.com",
    description="Instagram privacy protection and monitoring tools",
    long_description="Package for protecting Instagram accounts: hiding posts, monitoring followers/following, detecting suspicious activity",
    long_description_content_type="text/markdown",
    url="https://github.com/pymite6941/social-safe",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: End Users/Desktop",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
    python_requires=">=3.8",
    install_requires=[
        "instaloader>=4.8.0",
    ],
    entry_points={
        "console_scripts": [
            "socialsafe-monitor=socialsafe.monitor:monitor_instagram",
        ],
    },
)
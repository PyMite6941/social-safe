from setuptools import setup, find_packages

setup(
    name="socialsafe",
    version="0.1.0",
    author="pymite6941",
    author_email="you@example.com",
    description="Social media privacy protection and monitoring tools",
    long_description="Package for protecting social media accounts: monitoring followers/following, detecting suspicious activity, privacy auditing, and content scanning",
    long_description_content_type="text/markdown",
    url="https://github.com/pymite6941/social-safe",
    project_urls={
        "Bug Tracker": "https://github.com/pymite6941/social-safe/issues",
        "Documentation": "https://github.com/pymite6941/social-safe#readme",
        "Source Code": "https://github.com/pymite6941/social-safe",
    },
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
        "tweepy>=4.14.0",
        "praw>=7.7.0",
        "playwright>=1.64.0",
    ],
    entry_points={
        "console_scripts": [
            "socialsafe-monitor=socialsafe.monitor:monitor_instagram",
        ],
    },
)

import setuptools

from CamReaper import __version__

with open("README.md", "r") as f:
    long_description = f.read()

setuptools.setup(
    name="CamReaper",
    version=__version__,
    description="Asynchronous RTSP stream scanner with screenshots and gallery",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="p5uqt",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.13",
        "Topic :: Internet",
        "Topic :: Multimedia :: Video :: Capture",
        "Topic :: Security",
        "Topic :: Utilities",
    ],
    keywords="netstalking rtsp brute cctv",
    packages=setuptools.find_packages(),
    install_requires=["av", "Pillow", "tqdm"],
    python_requires=">=3.8",
    package_data={"CamReaper": ["credentials.txt", "routes.txt"]},
    entry_points={"console_scripts": ["CamReaper = CamReaper.__main__:main"]},
)

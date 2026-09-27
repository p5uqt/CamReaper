import re
from pathlib import Path

import setuptools

HERE = Path(__file__).parent
# Read the version out of the source instead of importing the package: a PEP 517
# build runs setup.py in an isolated environment where CamReaper is not
# importable, and importing it there fails the whole build.
VERSION = re.search(
    r'^__version__\s*=\s*["\']([^"\']+)["\']',
    (HERE / "CamReaper" / "__init__.py").read_text(encoding="utf-8"),
    re.MULTILINE,
).group(1)

long_description = (HERE / "README.md").read_text(encoding="utf-8")

setuptools.setup(
    name="CamReaper",
    version=VERSION,
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
    # The real data files are defroutes / defcreds (see CamReaper/__init__.py)
    # plus the vendor and CVE tables.  The previous list named files that do not
    # exist ("credentials.txt", "routes.txt"), so a wheel installed none of
    # them and every default -r / -c / vendor lookup / --mode cve run failed
    # with FileNotFoundError.
    package_data={
        "CamReaper": ["defroutes", "defcreds", "vendors.json", "cve_db.json"]
    },
    include_package_data=True,
    entry_points={"console_scripts": ["CamReaper = CamReaper.__main__:main"]},
)

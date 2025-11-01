from setuptools import setup, find_packages
from pathlib import Path

README = Path(__file__).with_name("README.md").read_text(encoding="utf-8")

setup(
    name="pysec_auditor",
    version="10.8.0",
    description="PySec Auditor - HTTP & TLS defensive auditing toolkit",
    long_description=README,
    long_description_content_type="text/markdown",
    author="Sardidev",
    license="MIT",
    packages=find_packages(),
    install_requires=[
        "requests", "beautifulsoup4", "pyfiglet", "rich"
    ],
    project_urls={
        "Homepage": "https://github.com/otakukazzee/PySec-Auditor",
        "Contributors": "https://github.com/otakukazzee/PySec-Auditor/graphs/contributors",
        "Documentation": "https://github.com/otakukazzee/PySec-Auditor/wiki",
    },
    include_package_data=True,
    python_requires=">=3.9",
)

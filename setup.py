from setuptools import setup, find_namespace_packages

setup(
    name="tls",
    version="0.1",
    package_dir={"": "pcap_creator"},  # מציין שהחבילות נמצאות בתיקיית pcap_creator
    packages=find_namespace_packages(where="pcap_creator"),  # מחפש חבילות בתיקיית pcap_creator
    install_requires=[
        # התלויות שלך מתוך requirements.txt
    ],
)
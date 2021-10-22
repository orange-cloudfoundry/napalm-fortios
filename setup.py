from setuptools import setup, find_packages

with open("requirements.txt", "r") as file:
    reqs = [req for req in file.read().splitlines() if (len(req) > 0 and not req.startswith("#"))]
__author__ = 'Arthur Halet <arthur.halet@orange.com>'

setup(
    name="napalm-fortios",
    version="0.1.0",
    packages=find_packages(),
    author="Arthur Halet",
    author_email="arthur.halet@orange.com",
    description="Network Automation and Programmability Abstraction Layer with Multivendor support",
    classifiers=[
        'Topic :: Utilities',
        'Programming Language :: Python :: 3.6',
        'Operating System :: POSIX :: Linux',
        'Operating System :: MacOS',
    ],
    url="https://github.com/napalm-automation-community/tbd",
    include_package_data=True,
    install_requires=reqs,
)

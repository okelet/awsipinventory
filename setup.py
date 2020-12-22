from pkg_resources import parse_requirements
from setuptools import setup

setup(
    name='awsipinventory',
    version='0.1',
    install_requires=[str(x) for x in parse_requirements(open('requirements.txt').readlines())],
    packages=["awsipinventory"],
    entry_points={
        'console_scripts': ['awsipinventory=awsipinventory:cli'],
    },
    include_package_data=True,
    url="https://github.com/okelet/awsipinventory",
    author="Juan A. S.",
    author_email="okelet@gmail.com",
)

#!/usr/bin/env python3

from setuptools import find_packages, setup

setup(
  name='EclypsesECDH',
  version='1.0.1',
  packages=find_packages(
    exclude=['__pycache__','EclypsesECDHCrossTest'],
    include=['EclypsesECDH']
    ),
  py_modules=['EclypsesECDH'],
  description='Elliptic Curve Diffie Hellman Key Generator',
  author='Eclypses', ## Change?
  license='NULL', ## Change
  install_requires=[
    'cryptography>=2.8',
    'setuptools>=45.2.0'
  ]
)
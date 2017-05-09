#!/usr/bin/env python

from setuptools import setup

setup(name='Crypt_Client',
      version='1.0',
      description='Socket-based cryptographic client',
      author='Juan Toca',
      author_email='elan17.programacion@gmail.com',
      packages=['Crypt_Client'],
      install_requires=['pycryptodome']
      )

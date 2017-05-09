#!/usr/bin/env python

from setuptools import setup

setup(name='Crypt_Server',
      version='1.0',
      description='Socket-based cryptographic server',
      author='Juan Toca',
      author_email='elan17.programacion@gmail.com',
      packages=['Crypt_Server'],
      install_requires=['pycryptodome']
      )

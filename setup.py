#!/usr/bin/env python

from setuptools import setup

setup(name='Crypt_Connection',
      version='1.0',
      description='Socket-based cryptographic server-client',
      author='Juan Toca',
      author_email='elan17.programacion@gmail.com',
      packages=['Crypt_Client', 'Crypt_Server'],
      provides=['Crypt_Client', 'Crypt_Server'],
      install_requires=['pycryptodome']
      )

#!/usr/bin/python
# The MIT License (MIT).
# Copyright (c) 2022 ALIF-FUSOBAR.

# $Id$

import glob
import os

from distutils.core import setup

PACKAGE_NAME = "impacket"

setup(name = PACKAGE_NAME,
      version = "0.9.16-dev",
      description = "Network protocols Constructors and Dissectors",
      url = "https://www.coresecurity.com/corelabs-research/open-source-tools/impacket",
      author = "The Cracker Technology",
      author_email = "weidsom@thecrackertechnology.com",
      maintainer = "ALIF FUSOBAR",
      maintainer_email = "sachihenakyy@gmail.com",
      license = "MIT Modified",
      long_description = 'Impacket is a collection of Python classes focused on providing access to network packets. Impacket allows Python developers to craft and decode network packets in simple and consistent manner.',
      platforms = ["Unix","Windows"],
      packages = ['impacket', 'impacket.dcerpc', 'impacket.examples', 'impacket.dcerpc.v5', 'impacket.dcerpc.v5.dcom', 'impacket.krb5', 'impacket.ldap', 'impacket.examples.ntlmrelayx', 'impacket.examples.ntlmrelayx.clients', 'impacket.examples.ntlmrelayx.servers', 'impacket.examples.ntlmrelayx.utils'],
      scripts = glob.glob(os.path.join('examples', '*.py')),
      data_files = [(os.path.join('share', 'doc', PACKAGE_NAME), ['README.md', 'LICENSE']+glob.glob('doc/*')),
                    (os.path.join('share', 'doc', PACKAGE_NAME, 'testcases', 'dot11'),glob.glob('impacket/testcases/dot11/*')),
                    (os.path.join('share', 'doc', PACKAGE_NAME, 'testcases', 'ImpactPacket'),glob.glob('impacket/testcases/ImpactPacket/*')),
                    (os.path.join('share', 'doc', PACKAGE_NAME, 'testcases', 'SMB_RPC'),glob.glob('impacket/testcases/SMB_RPC/*'))],
      requires=['pycrypto (>=2.6)', 'pyasn1 (>=0.1.7)'],
      )

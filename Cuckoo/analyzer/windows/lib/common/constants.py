#!/usr/bin/env python
# The MIT License (MIT).
# Copyright (c) 2022 ALIF-FUSOBAR.
# See the file 'docs/LICENSE' for copying permission.

import os
from lib.common.rand import random_string


ROOT = os.path.join(os.getenv("SystemDrive"), "\\", random_string(6, 10))

PATHS = {"root"   : ROOT,
         "logs"   : os.path.join(ROOT, "logs"),
         "files"  : os.path.join(ROOT, "files"),
         "shots"  : os.path.join(ROOT, "shots"),
         "memory" : os.path.join(ROOT, "memory"),
         "drop"   : os.path.join(ROOT, "drop")}

PIPE = "\\\\.\\PIPE\\" + random_string(6, 10)

#!/usr/bin/env python
# The MIT License (MIT).
# Copyright (c) 2022 ALIF-FUSOBAR.
# See the file 'docs/LICENSE' & 'docs/README' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class CreatesExe(Signature):
    name = "creates_exe"
    description = "Creates a Windows executable on the filesystem"
    severity = 2
    categories = ["generic"]
    authors = ["Cuckoo Developers"]
    minimum = "0.5"

    # This is a signature template. It should be used as a skeleton for
    # creating custom signatures, therefore is disabled by default.
    # It doesn't verify whether a .exe is actually being created, but
    # it matches files being opened with any access type, including
    # read and attributes lookup.
    enabled = False

    def run(self):
        match = self.check_file(pattern=".*\\.exe$",
                                regex=True)
        if match:
            self.data.append({"file": match})
            return True

        return False

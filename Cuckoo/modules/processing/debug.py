#!/usr/bin/env python
# The MIT License (MIT).
# Copyright (c) 2022 ALIF-FUSOBAR.
# See the file 'docs/LICENSE' & 'docs/README' for copying permission.

import os
import codecs

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.exceptions import CuckooProcessingError
from lib.cuckoo.core.database import Database

class Debug(Processing):
    """Analysis debug information."""

    def run(self):
        """Run debug analysis.
        @return: debug information dict.
        """
        self.key = "debug"
        debug = {"log": "", "errors": []}

        if os.path.exists(self.log_path):
            try:
                debug["log"] = codecs.open(self.log_path, "rb", "utf-8").read()
            except ValueError as e:
                raise CuckooProcessingError("Error decoding %s: %s" %
                                            (self.log_path, e))
            except (IOError, OSError) as e:
                raise CuckooProcessingError("Error opening %s: %s" %
                                            (self.log_path, e))

        for error in Database().view_errors(int(self.task["id"])):
            debug["errors"].append(error.message)

        return debug

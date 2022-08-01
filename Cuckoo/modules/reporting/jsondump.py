#!/usr/bin/env python
# The MIT License (MIT).
# Copyright (c) 2022 ALIF-FUSOBAR.
# See the file 'docs/LICENSE' & 'docs/README' for copying permission.

import os
import json
import codecs

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooReportError

class JsonDump(Report):
    """Saves analysis results in JSON format."""

    def run(self, results):
        """Writes report.
        @param results: Cuckoo results dict.
        @raise CuckooReportError: if fails to write report.
        """
        try:
            path = os.path.join(self.reports_path, "report.json")
            report = codecs.open(path, "w", "utf-8")
            json.dump(results, report, sort_keys=False, indent=4)
            report.close()
        except (UnicodeError, TypeError, IOError) as e:
            raise CuckooReportError("Failed to generate JSON report: %s" % e)

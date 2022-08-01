#!/usr/bin/env python
# The MIT License (MIT).
# Copyright (c) 2022 ALIF-FUSOBAR.
# See the file 'docs/LICENSE' & 'docs/README' for copying permission.

import sys

from django.conf import settings

sys.path.append(settings.CUCKOO_PATH)

from lib.cuckoo.common.constants import CUCKOO_VERSION

class CuckooHeaders(object):
    """Set Cuckoo custom response headers."""

    def process_response(self, request, response):
        response["Server"] = "Machete Server"
        response["X-Cuckoo-Version"] = CUCKOO_VERSION
        response["X-Content-Type-Options"] = "nosniff"
        response["X-Frame-Options"] = "DENY"
        response["X-XSS-Protection"] = "1; mode=block"
        response["Pragma"] = "no-cache"
        response["Cache-Control"] = "no-cache"
        response["Expires"] = "0"

        return response
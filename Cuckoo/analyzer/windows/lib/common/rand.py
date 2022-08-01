#!/usr/bin/env python
# The MIT License (MIT).
# Copyright (c) 2022 ALIF-FUSOBAR.
# See the file 'docs/LICENSE' for copying permission.

import random
import string

def random_string(minimum, maximum=None):
    if maximum is None:
        maximum = minimum

    count = random.randint(minimum, maximum)
    return "".join(random.choice(string.ascii_letters) for x in xrange(count))

def random_integer(digits):
    start = 10 ** (digits - 1)
    end = (10 ** digits) - 1
    return random.randint(start, end)

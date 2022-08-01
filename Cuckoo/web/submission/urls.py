#!/usr/bin/env python
# The MIT License (MIT).
# Copyright (c) 2022 ALIF-FUSOBAR.
# See the file 'docs/LICENSE' & 'docs/README' for copying permission.

from django.conf.urls import patterns, url

urlpatterns = patterns("",
    url(r"^$", "submission.views.index"),
)

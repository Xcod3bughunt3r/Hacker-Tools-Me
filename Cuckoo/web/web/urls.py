#!/usr/bin/env python
# The MIT License (MIT).
# Copyright (c) 2022 ALIF-FUSOBAR.
# See the file 'docs/LICENSE' & 'docs/README' for copying permission.

from django.conf.urls import patterns, include, url

urlpatterns = patterns("",
    url(r"^$", "dashboard.views.index"),
    url(r"^analysis/", include("analysis.urls")),
    url(r"^submit/", include("submission.urls")),
    url(r"^file/(?P<category>\w+)/(?P<object_id>\w+)/$", "analysis.views.file"),
    url(r"^dashboard/", include("dashboard.urls")),
)
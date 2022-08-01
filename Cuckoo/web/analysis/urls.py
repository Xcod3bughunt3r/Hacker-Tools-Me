#!/usr/bin/env python
# The MIT License (MIT).
# Copyright (c) 2022 ALIF-FUSOBAR.
# See the file 'docs/LICENSE' & 'docs/README' for copying permission.

from django.conf.urls import patterns, url

urlpatterns = patterns("",
    url(r"^$", "analysis.views.index"),
    url(r"^(?P<task_id>\d+)/$", "analysis.views.report"),
    url(r"^chunk/(?P<task_id>\d+)/(?P<pid>\d+)/(?P<pagenum>\d+)/$", "analysis.views.chunk"),
    url(r"^filtered/(?P<task_id>\d+)/(?P<pid>\d+)/(?P<category>\w+)/$", "analysis.views.filtered_chunk"),
    url(r"^search/$", "analysis.views.search"),
    url(r"^pending/$", "analysis.views.pending"),
)

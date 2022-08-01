#!/usr/bin/env python
# The MIT License (MIT).
# Copyright (c) 2022 ALIF-FUSOBAR.
# See the file 'docs/LICENSE' & 'docs/README' for copying permission.

from django import forms

from submission.models import Comment, Tag

class CommentForm(forms.ModelForm):
    class Meta:
        model = Comment
        fields = ["message"]

class TagForm(forms.ModelForm):
    class Meta:
        model = Tag
        fields = ["name"]

#!/usr/bin/env python
# The MIT License (MIT).
# Copyright (c) 2022 ALIF-FUSOBAR.
# See the file 'docs/LICENSE' & 'docs/README' for copying permission.

from lib.cuckoo.common.abstracts import LibVirtMachinery

class KVM(LibVirtMachinery):
    """Virtualization layer for KVM based on python-libvirt."""

    # Set KVM connection string.
    dsn = "qemu:///system"

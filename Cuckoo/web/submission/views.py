#!/usr/bin/env python
# The MIT License (MIT).
# Copyright (c) 2022 ALIF-FUSOBAR.
# See the file 'docs/LICENSE' & 'docs/README' for copying permission.

import os
import sys

from django.conf import settings
from django.shortcuts import render_to_response
from django.template import RequestContext

sys.path.append(settings.CUCKOO_PATH)

from lib.cuckoo.core.database import Database
from lib.cuckoo.common.utils import store_temp_file

def force_int(value):
    try:
        value = int(value)
    except:
        value = 0
    finally:
        return value

def index(request):
    if request.method == "POST":
        package = request.POST.get("package", "")
        timeout = force_int(request.POST.get("timeout"))
        options = request.POST.get("options", "")
        priority = force_int(request.POST.get("priority"))
        machine = request.POST.get("machine", "")
        custom = request.POST.get("custom", "")
        memory = bool(request.POST.get("memory", False))
        enforce_timeout = bool(request.POST.get("enforce_timeout", False))
        tags = request.POST.get("tags", None)

        if request.POST.get("free"):
            if options:
                options += "&"
            options += "free=yes"

        if request.POST.get("process_memory"):
            if options:
                options += "&"
            options += "procmemdump=yes"

        db = Database()
        task_ids = []
        task_machines = []

        if machine.lower() == "all":
            for entry in db.list_machines():
                task_machines.append(entry.label)
        else:
            task_machines.append(machine)

        if "sample" in request.FILES:
            if request.FILES["sample"].size == 0:
                return render_to_response("error.html",
                                          {"error": "You uploaded an empty file."},
                                          context_instance=RequestContext(request))
            elif request.FILES["sample"].size > settings.MAX_UPLOAD_SIZE:
                return render_to_response("error.html",
                                          {"error": "You uploaded a file that exceeds that maximum allowed upload size."},
                                          context_instance=RequestContext(request))

            # Moving sample from django temporary file to Cuckoo temporary storage to
            # let it persist between reboot (if user like to configure it in that way).
            path = store_temp_file(request.FILES["sample"].read(),
                                   request.FILES["sample"].name)

            for entry in task_machines:
                task_id = db.add_path(file_path=path,
                                      package=package,
                                      timeout=timeout,
                                      options=options,
                                      priority=priority,
                                      machine=entry,
                                      custom=custom,
                                      memory=memory,
                                      enforce_timeout=enforce_timeout,
                                      tags=tags)
                if task_id:
                    task_ids.append(task_id)
        elif "url" in request.POST:
            url = request.POST.get("url").strip()
            if not url:
                return render_to_response("error.html",
                                          {"error": "You specified an invalid URL!"},
                                          context_instance=RequestContext(request))

            for entry in task_machines:
                task_id = db.add_url(url=url,
                                     package=package,
                                     timeout=timeout,
                                     options=options,
                                     priority=priority,
                                     machine=entry,
                                     custom=custom,
                                     memory=memory,
                                     enforce_timeout=enforce_timeout,
                                     tags=tags)
                if task_id:
                    task_ids.append(task_id)

        tasks_count = len(task_ids)
        if tasks_count > 0:
            if tasks_count == 1:
                message = "The analysis task was successfully added with ID {0}.".format(task_ids[0])
            else:
                message = "The analysis task were successfully added with IDs {0}.".format(", ".join(str(i) for i in task_ids))

            return render_to_response("success.html",
                                      {"message": message},
                                      context_instance=RequestContext(request))
        else:
            return render_to_response("error.html",
                                      {"error": "Error adding task to Cuckoo's database."},
                                      context_instance=RequestContext(request))
    else:
        files = os.listdir(os.path.join(settings.CUCKOO_PATH, "analyzer", "windows", "modules", "packages"))

        packages = []
        for name in files:
            name = os.path.splitext(name)[0]
            if name == "__init__":
                continue

            packages.append(name)

        # Prepare a list of VM names, description label based on tags.
        machines = []
        for machine in Database().list_machines():
            tags = []
            for tag in machine.tags:
                tags.append(tag.name)

            if len(tags) > 0:
                label = machine.name + ": " + ", ".join(tags) 
            else:
                label = machine.name

            machines.append((machine.name, label))

        # Prepend ALL/ANY options.
        machines.insert(0, ("", "First available"))
        machines.insert(1, ("all", "All"))

        return render_to_response("submission/index.html",
                                  {"packages": sorted(packages),
                                   "machines": machines},
                                  context_instance=RequestContext(request))

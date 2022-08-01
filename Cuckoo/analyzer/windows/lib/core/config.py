#!/usr/bin/env python
# The MIT License (MIT).
# Copyright (c) 2022 ALIF-FUSOBAR.
# See the file 'docs/LICENSE' for copying permission.

import ConfigParser

class Config:
    def __init__(self, cfg):
        """@param cfg: configuration file."""
        config = ConfigParser.ConfigParser(allow_no_value=True)
        config.read(cfg)

        for section in config.sections():
            for name, raw_value in config.items(section):
                if name == "file_name":
                    value = config.get(section, name)
                else:
                    try:
                        value = config.getboolean(section, name)
                    except ValueError:
                        try:
                            value = config.getint(section, name)
                        except ValueError:
                            value = config.get(section, name)
                setattr(self, name, value)

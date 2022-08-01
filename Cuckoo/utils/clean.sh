#!/usr/bin/bash
# The MIT License (MIT).
# Copyright (c) 2022 ALIF-FUSOBAR.
# See the file 'docs/LICENSE' & 'docs/README' for copying permission.

# I'm sure this can be done easier, but I'm not very familiar with bash
# scripting.. So, here we go. Also, this only works from "./cuckoo" and
# "./cuckoo/utils" directory, but it's still better than before.
if [[ $PWD/ = */utils/ ]]; then
    export PWD=${PWD:0:${#PWD}-6}
fi

rm -rf $PWD/db/ $PWD/log/ $PWD/storage/
find $PWD/ -name '*.pyc' -exec rm {} \;

#!/bin/bash

cd ~/pintos
cd src && make clean
cd ~/pintos && tar --exclude=src/misc/bochs -cvzf submission.tgz src/

#! /bin/bash

sudo ./app/x86_64-native-linuxapp-gcc/pktgen -l 0-9 -n 3 -- -P -m "[1-2:3-4].0, [5-6:7-8].1" -s 1:$1
